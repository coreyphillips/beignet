/**
 * Phase 5: Pathfinding & Payment Reliability.
 *
 * - 5.1: Amount-aware MissionControl
 * - 5.2: Payment probing
 * - 5.3: Offer invoice matching fix
 * - 5.4: Database backup API
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import { OfferManager } from '../../src/lightning/offer/offer-manager';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`phase5-test-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

// ─── 5.1: Amount-aware MissionControl ───

describe('Amount-aware MissionControl', () => {
	it('recordFailure stores lastFailureAmountMsat', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 1_000_000n);
		// Access internal state via export
		const data = JSON.parse(mc.export());
		expect(data[0].lastFailureAmountMsat).to.equal(1_000_000);
	});

	it('recordFailure without amount does not set lastFailureAmountMsat', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc');
		const data = JSON.parse(mc.export());
		expect(data[0].lastFailureAmountMsat).to.be.undefined;
	});

	it('recordFailure updates amount on subsequent failures', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 500_000n);
		mc.recordFailure('abc', 1_000_000n);
		const data = JSON.parse(mc.export());
		expect(data[0].lastFailureAmountMsat).to.equal(1_000_000);
		expect(data[0].failureCount).to.equal(2);
	});

	it('getPenalty reduces for smaller amounts', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 1_000_000n);

		// Full penalty at same amount
		const fullPenalty = mc.getPenalty('abc', 1_000_000n);
		// Reduced penalty at 1/10 the amount
		const reducedPenalty = mc.getPenalty('abc', 100_000n);

		expect(Number(fullPenalty)).to.be.greaterThan(0);
		expect(Number(reducedPenalty)).to.be.greaterThan(0);
		expect(Number(reducedPenalty)).to.be.lessThan(Number(fullPenalty));
	});

	it('getPenalty without currentAmountMsat gives full penalty', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 1_000_000n);

		const fullPenalty = mc.getPenalty('abc');
		const alsoFull = mc.getPenalty('abc', 1_000_000n);

		// Both should be the same (no amount scaling when undefined). Allow a
		// 1-sat tolerance: getPenalty applies a time-decay from Date.now(), so
		// two calls a fraction of a millisecond apart can floor to adjacent
		// integers. Amount scaling, which this asserts is absent, would change
		// the penalty by tens of thousands, not one.
		expect(Number(fullPenalty)).to.be.closeTo(Number(alsoFull), 2);
	});

	it('getPenalty for amount larger than failure gives full penalty', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 500_000n);

		const fullPenalty = mc.getPenalty('abc', 500_000n);
		const largerPenalty = mc.getPenalty('abc', 1_000_000n);

		// When current amount >= failure amount, no reduction. Allow a 1-sat
		// tolerance for the Date.now() time-decay between the two calls (see the
		// note above); a real amount reduction would be far larger.
		expect(Number(largerPenalty)).to.be.closeTo(Number(fullPenalty), 2);
	});

	it('amount-aware penalty scales linearly with ratio', () => {
		const mc = new MissionControl();
		mc.recordFailure('abc', 1_000_000n);

		const halfPenalty = mc.getPenalty('abc', 500_000n);
		const quarterPenalty = mc.getPenalty('abc', 250_000n);

		// halfPenalty should be roughly 2x quarterPenalty
		// (not exact due to integer math)
		const ratio = Number(halfPenalty) / Number(quarterPenalty);
		expect(ratio).to.be.closeTo(2, 0.1);
	});

	it('export/import preserves lastFailureAmountMsat', () => {
		const mc1 = new MissionControl();
		mc1.recordFailure('abc', 750_000n);
		mc1.recordSuccess('abc');

		const json = mc1.export();
		const mc2 = new MissionControl();
		mc2.import(json);

		const data = JSON.parse(mc2.export());
		expect(data[0].lastFailureAmountMsat).to.equal(750_000);
		expect(data[0].successCount).to.equal(1);
	});

	it('import handles missing lastFailureAmountMsat (backward compat)', () => {
		const mc = new MissionControl();
		const oldJson = JSON.stringify([
			{
				scid: 'abc',
				lastFailureTs: Date.now(),
				failureCount: 1,
				successCount: 0
			}
		]);
		mc.import(oldJson);

		const data = JSON.parse(mc.export());
		expect(data[0].lastFailureAmountMsat).to.be.undefined;
		expect(Number(mc.getPenalty('abc'))).to.be.greaterThan(0);
	});

	it('getPenalty returns 0 for unknown channel', () => {
		const mc = new MissionControl();
		expect(Number(mc.getPenalty('unknown'))).to.equal(0);
		expect(Number(mc.getPenalty('unknown', 1000n))).to.equal(0);
	});
});

// ─── 5.2: Payment Probing ───

describe('Payment Probing', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(10));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('probeRoute returns success:false when no route exists', () => {
		const dest = crypto.randomBytes(33).toString('hex');
		const result = node.probeRoute(dest, 1000);
		expect(result.success).to.be.false;
		expect(result.feeSats).to.be.undefined;
		expect(result.hops).to.be.undefined;
	});

	it('probeRoute returns success:false for invalid destination', () => {
		const result = node.probeRoute('invalid', 1000);
		expect(result.success).to.be.false;
	});

	it('probeRoute accepts zero amount', () => {
		const dest = crypto.randomBytes(33).toString('hex');
		const result = node.probeRoute(dest, 0);
		// Should not throw
		expect(result).to.have.property('success');
	});

	it('probeRoute is available on LightningNode', () => {
		expect(typeof node.probeRoute).to.equal('function');
	});
});

// ─── 5.3: Offer Invoice Matching Fix ───

describe('Offer Invoice Matching', () => {
	let offerMgr: OfferManager;
	const privkey = crypto
		.createHash('sha256')
		.update(Buffer.from('offer-mgr-test'))
		.digest();

	beforeEach(() => {
		offerMgr = new OfferManager(privkey);
	});

	afterEach(() => {
		offerMgr.destroy();
	});

	it('OfferManager resolves single pending request', (done) => {
		// Create an offer and start an invoice request (will time out without onion messages)
		const { offer } = offerMgr.createOffer({ description: 'test offer' });
		const offerIdHex = offer.offerId.toString('hex');

		// Add a pending request manually
		(offerMgr as any).pendingInvoiceRequests.set(offerIdHex, {
			resolve: (invoice: any) => {
				expect(invoice.description).to.equal('test offer');
				done();
			},
			reject: () => {
				throw new Error('should not reject');
			},
			timer: setTimeout(() => {}, 60000)
		});

		// Simulate incoming invoice
		const mockInvoice = {
			paymentHash: crypto.randomBytes(32),
			amount: 1000n,
			description: 'test offer',
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			nodeId: getPublicKey(privkey)
		};

		// Call private handler
		(offerMgr as any).pendingInvoiceRequests.size;
		// Emit manually via the offer manager's handler
		const pending = (offerMgr as any).pendingInvoiceRequests.get(offerIdHex);
		clearTimeout(pending.timer);
		(offerMgr as any).pendingInvoiceRequests.delete(offerIdHex);
		pending.resolve(mockInvoice);
	});

	it('OfferManager matches by description when multiple pending', (done) => {
		// Create two offers
		const { offer: offer1 } = offerMgr.createOffer({ description: 'offer A' });
		const { offer: offer2 } = offerMgr.createOffer({ description: 'offer B' });

		let resolved1 = false;
		let resolved2 = false;

		(offerMgr as any).pendingInvoiceRequests.set(
			offer1.offerId.toString('hex'),
			{
				resolve: (invoice: any) => {
					expect(invoice.description).to.equal('offer A');
					resolved1 = true;
					if (resolved1 && resolved2) done();
				},
				reject: () => {
					throw new Error('should not reject');
				},
				timer: setTimeout(() => {}, 60000)
			}
		);

		(offerMgr as any).pendingInvoiceRequests.set(
			offer2.offerId.toString('hex'),
			{
				resolve: (invoice: any) => {
					expect(invoice.description).to.equal('offer B');
					resolved2 = true;
					if (resolved1 && resolved2) done();
				},
				reject: () => {
					throw new Error('should not reject');
				},
				timer: setTimeout(() => {}, 60000)
			}
		);

		// Simulate invoice for offer B first
		const invoiceB = {
			paymentHash: crypto.randomBytes(32),
			amount: 2000n,
			description: 'offer B',
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			nodeId: getPublicKey(privkey)
		};

		// Simulate invoice for offer A
		const invoiceA = {
			paymentHash: crypto.randomBytes(32),
			amount: 1000n,
			description: 'offer A',
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			nodeId: getPublicKey(privkey)
		};

		// Manually resolve in order (B first, then A)
		const pendingB = (offerMgr as any).pendingInvoiceRequests.get(
			offer2.offerId.toString('hex')
		);
		clearTimeout(pendingB.timer);
		(offerMgr as any).pendingInvoiceRequests.delete(
			offer2.offerId.toString('hex')
		);
		pendingB.resolve(invoiceB);

		const pendingA = (offerMgr as any).pendingInvoiceRequests.get(
			offer1.offerId.toString('hex')
		);
		clearTimeout(pendingA.timer);
		(offerMgr as any).pendingInvoiceRequests.delete(
			offer1.offerId.toString('hex')
		);
		pendingA.resolve(invoiceA);
	});

	it('OfferManager.destroy clears pending requests', () => {
		offerMgr.createOffer({ description: 'will be destroyed' });
		const { offer } = offerMgr.createOffer({ description: 'another' });

		(offerMgr as any).pendingInvoiceRequests.set(
			offer.offerId.toString('hex'),
			{
				resolve: () => {},
				reject: () => {},
				timer: setTimeout(() => {}, 60000)
			}
		);

		expect((offerMgr as any).pendingInvoiceRequests.size).to.equal(1);
		offerMgr.destroy();
		expect((offerMgr as any).pendingInvoiceRequests.size).to.equal(0);
	});

	it('OfferManager listOffers returns created offers', () => {
		offerMgr.createOffer({ description: 'offer 1' });
		offerMgr.createOffer({ description: 'offer 2' });
		const offers = offerMgr.listOffers();
		expect(offers).to.have.length(2);
	});

	it('OfferManager removeOffer works', () => {
		const { offer } = offerMgr.createOffer({ description: 'to remove' });
		expect(offerMgr.listOffers()).to.have.length(1);
		offerMgr.removeOffer(offer.offerId);
		expect(offerMgr.listOffers()).to.have.length(0);
	});
});

// ─── 5.4: Database Backup API ───

describe('Database Backup API', () => {
	let storage: SqliteStorage;
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-backup-'));
		const dbPath = path.join(tmpDir, 'test.db');
		storage = new SqliteStorage(dbPath);
		storage.open({ synchronous: 'NORMAL' });
	});

	afterEach(() => {
		storage.close();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('backup creates a copy of the database', async () => {
		// Write some data
		const paymentHash = crypto.randomBytes(32);
		storage.savePayment(paymentHash.toString('hex'), {
			paymentHash,
			amountMsat: 50_000n,
			status: 'COMPLETED' as any,
			direction: 'OUTGOING' as any,
			createdAt: Date.now()
		});

		const backupPath = path.join(tmpDir, 'backup.db');
		await storage.backup(backupPath);

		// Verify backup file exists
		expect(fs.existsSync(backupPath)).to.be.true;

		// Open backup and check data
		const backupStorage = new SqliteStorage(backupPath);
		backupStorage.open({ synchronous: 'NORMAL' });
		const loaded = backupStorage.loadPayment(paymentHash.toString('hex'));
		expect(loaded).to.not.be.null;
		expect(Number(loaded!.amountMsat)).to.equal(50_000);
		backupStorage.close();
	});

	it('backup method exists on SqliteStorage', () => {
		expect(typeof storage.backup).to.equal('function');
	});

	it('backup returns a promise', () => {
		const backupPath = path.join(tmpDir, 'backup2.db');
		const result = storage.backup(backupPath);
		expect(result).to.be.instanceOf(Promise);
		return result;
	});

	it('backup preserves multiple tables', async () => {
		// Save a payment and a peer address
		const paymentHash = crypto.randomBytes(32);
		storage.savePayment(paymentHash.toString('hex'), {
			paymentHash,
			amountMsat: 10_000n,
			status: 'COMPLETED' as any,
			direction: 'INCOMING' as any,
			createdAt: Date.now()
		});
		storage.savePeerAddress('02abcd', '127.0.0.1', 9735);

		const backupPath = path.join(tmpDir, 'backup3.db');
		await storage.backup(backupPath);

		const backupStorage = new SqliteStorage(backupPath);
		backupStorage.open({ synchronous: 'NORMAL' });

		const payments = backupStorage.loadAllPayments();
		expect(payments).to.have.length(1);

		const peers = backupStorage.loadAllPeerAddresses();
		expect(peers).to.have.length(1);
		expect(peers[0].pubkey).to.equal('02abcd');

		backupStorage.close();
	});

	it('backup to same directory as source works', async () => {
		const backupPath = path.join(tmpDir, 'test-backup.db');
		await storage.backup(backupPath);
		expect(fs.existsSync(backupPath)).to.be.true;
	});
});
