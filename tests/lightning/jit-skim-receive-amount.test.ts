/**
 * A JIT skim receive records what it was credited (issue #1869).
 *
 * In skim mode the LSP takes its opening fee out of a forward whose onion it
 * cannot rewrite, so the receiver settles an HTLC short of the onion's
 * amt_to_forward. The final hop validated the invoice against the declared
 * amount and then wrote that same amount as what it received, so a 20,000
 * sat invoice skimmed 120 sat read 20,000 while the channel gained 19,880.
 *
 * Alice pays Charlie through Bob. Bob stands in for the LSP: his forward to
 * Charlie is cut by the skim, which is what Charlie's invoice allowance
 * admits. The record keeps the invoice amount it was validated against and
 * notes the credited figure in receivedMsat, which must match the channel's
 * balance change and the row a restart reads.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	deserializePaymentInfo,
	serializePaymentInfo
} from '../../src/lightning/storage/serialization';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`jit-skim-amount-${id}`))
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
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

function createNode(seedId: number, storage?: SqliteStorage): LightningNode {
	const node = new LightningNode({
		...makeNodeConfig(seedId),
		...(storage ? { storage } : {})
	});
	node.on('node:error', () => {});
	return node;
}

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

const SCID_AB = encodeShortChannelId({
	block: 600,
	txIndex: 1,
	outputIndex: 0
});
const SCID_BC = encodeShortChannelId({
	block: 600,
	txIndex: 2,
	outputIndex: 0
});
const HEIGHT = 1000;
const BOB_FEE_MSAT = 500n;

// The issue's figures: 20,000 sat with 100 sat flat and 1,000 ppm, 120 sat.
const INVOICE_MSAT = 20_000_000n;
const JIT_FEE = { flatFeeSat: 100, feePpm: 1_000 };
const SKIM_MSAT = 120_000n;

interface IChain {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	charlieChannelId: Buffer;
	destroy: () => void;
}

/** Alice -> Bob -> Charlie, Charlie on durable storage. */
function setupChain(base: number, storage: SqliteStorage): IChain {
	const alice = createNode(base);
	const bob = createNode(base + 1);
	const charlie = createNode(base + 2, storage);
	wire(alice, bob);
	wire(bob, charlie);
	const openReady = (
		opener: LightningNode,
		acceptor: LightningNode,
		scid: Buffer
	): Buffer => {
		const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
		const channelId = opener.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		opener.handleFundingConfirmed(channelId);
		acceptor.handleFundingConfirmed(channelId);
		opener.registerChannelScid(channelId, scid);
		acceptor.registerChannelScid(channelId, scid);
		return channelId;
	};
	openReady(alice, bob, SCID_AB);
	const charlieChannelId = openReady(bob, charlie, SCID_BC);
	bob.setChannelPolicy(charlieChannelId, {
		feeBaseMsat: Number(BOB_FEE_MSAT),
		feeProportionalMillionths: 0
	});
	for (const node of [alice, bob, charlie]) node.handleNewBlock(HEIGHT);
	return {
		alice,
		bob,
		charlie,
		charlieChannelId,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			charlie.destroy();
		}
	};
}

/**
 * Bob forwards each HTLC for the hash short by the next skim in the list,
 * as an LSP in skim mode does; an exhausted list forwards in full.
 */
function skimForwards(bob: LightningNode, hash: Buffer, skims: bigint[]): void {
	const manager = bob.getChannelManager();
	const add = manager.addHtlc.bind(manager);
	manager.addHtlc = (
		channelId,
		amountMsat,
		paymentHash,
		...rest
	): ReturnType<typeof add> =>
		add(
			channelId,
			paymentHash.equals(hash)
				? amountMsat - (skims.shift() ?? 0n)
				: amountMsat,
			paymentHash,
			...rest
		);
}

/** Alice's part: Bob is paid finalMsat plus his fee and forwards finalMsat. */
function sendPart(
	chain: IChain,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer },
	finalMsat: bigint
): IPaymentInfo {
	return chain.alice.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(chain.bob.getNodeId(), 'hex'),
					shortChannelId: SCID_AB,
					amountToForwardMsat: finalMsat + BOB_FEE_MSAT,
					outgoingCltvValue: 80
				},
				{
					pubkey: Buffer.from(chain.charlie.getNodeId(), 'hex'),
					shortChannelId: SCID_BC,
					amountToForwardMsat: finalMsat,
					outgoingCltvValue: 40
				}
			]
		},
		invoice.paymentHash,
		40,
		invoice.paymentSecret,
		INVOICE_MSAT
	);
}

function localBalanceMsat(node: LightningNode, channelId: Buffer): bigint {
	return node.getChannelManager().getChannel(channelId)!.getFullState()
		.localBalanceMsat;
}

async function waitUntil(done: () => boolean, what: string): Promise<void> {
	const deadline = Date.now() + 5_000;
	while (!done()) {
		if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
}

/** Parts Charlie holds toward an MPP set for the hash. */
function heldParts(charlie: LightningNode, hash: Buffer): number {
	return (
		(
			charlie as unknown as {
				pendingMppPayments: Map<string, { receivedParts: unknown[] }>;
			}
		).pendingMppPayments.get(hash.toString('hex'))?.receivedParts.length ?? 0
	);
}

/** Pays the invoice whole and waits for Alice's record to resolve. */
async function payWhole(
	chain: IChain,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer }
): Promise<PaymentStatus | null> {
	sendPart(chain, invoice, INVOICE_MSAT);
	return (await chain.alice.awaitPaymentResolution(invoice.paymentHash, 5_000))
		.status;
}

/** Pays the invoice in two halves, the second once Charlie holds the first. */
async function payInHalves(
	chain: IChain,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer }
): Promise<void> {
	sendPart(chain, invoice, INVOICE_MSAT / 2n);
	await waitUntil(
		() => heldParts(chain.charlie, invoice.paymentHash) === 1,
		'the first part'
	);
	await waitUntil(
		() =>
			chain.alice
				.getChannelManager()
				.getChannelsByPeer(chain.bob.getNodeId())
				.some((channel) => channel.acceptsNewHtlcs()),
		'the channel to take the second part'
	);
	sendPart(chain, invoice, INVOICE_MSAT / 2n);
}

describe('JIT skim receive records the credited amount (issue #1869)', () => {
	const cleanup: Array<() => void> = [];
	afterEach(() => {
		for (const done of cleanup.splice(0).reverse()) done();
	});

	/** Charlie's storage is a file, so a restart can reopen it. */
	function chainOnStorage(base: number): {
		chain: IChain;
		storage: SqliteStorage;
		dbPath: string;
	} {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jit-skim-amount-'));
		cleanup.push(() => fs.rmSync(dir, { recursive: true, force: true }));
		const dbPath = path.join(dir, 'charlie.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const chain = setupChain(base, storage);
		cleanup.push(chain.destroy);
		return { chain, storage, dbPath };
	}

	it('a single-part skim records the invoice amount and what the channel was credited', async () => {
		const { chain, storage, dbPath } = chainOnStorage(10);
		const { charlie, charlieChannelId } = chain;
		const invoice = charlie.createInvoice({
			amountMsat: INVOICE_MSAT,
			description: 'jit skim',
			jitFeeAllowance: JIT_FEE
		});
		skimForwards(chain.bob, invoice.paymentHash, [SKIM_MSAT]);
		const before = localBalanceMsat(charlie, charlieChannelId);

		expect(await payWhole(chain, invoice)).to.equal(PaymentStatus.COMPLETED);

		const credited = localBalanceMsat(charlie, charlieChannelId) - before;
		expect(credited, 'the channel credits the skimmed HTLC').to.equal(
			INVOICE_MSAT - SKIM_MSAT
		);
		const record = charlie.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.amountMsat, 'the amount validated against').to.equal(
			INVOICE_MSAT
		);
		// Before the fix this was absent and the record read 20,000 sat.
		expect(record.receivedMsat, 'what the channel credited').to.equal(credited);

		const hashHex = invoice.paymentHash.toString('hex');
		expect(storage.loadPayment(hashHex)!.receivedMsat).to.equal(credited);
		charlie.destroy();
		const reopened = new SqliteStorage(dbPath);
		reopened.open();
		const restarted = createNode(12, reopened);
		cleanup.push(() => restarted.destroy());
		const restored = restarted.getPayment(invoice.paymentHash)!;
		expect(restored.amountMsat).to.equal(INVOICE_MSAT);
		expect(restored.receivedMsat, 'after a restart').to.equal(credited);
		expect(
			localBalanceMsat(restarted, charlieChannelId) - before,
			'the restored channel agrees'
		).to.equal(credited);
	});

	it('an MPP set with one part carrying the skim records the sum of its HTLCs', async () => {
		const { chain } = chainOnStorage(20);
		const { charlie, charlieChannelId } = chain;
		const invoice = charlie.createInvoice({
			amountMsat: INVOICE_MSAT,
			description: 'jit skim mpp',
			jitFeeAllowance: JIT_FEE
		});
		skimForwards(chain.bob, invoice.paymentHash, [SKIM_MSAT]);
		const before = localBalanceMsat(charlie, charlieChannelId);

		await payInHalves(chain, invoice);
		expect(
			(await chain.alice.awaitPaymentResolution(invoice.paymentHash, 5_000))
				.status
		).to.equal(PaymentStatus.COMPLETED);

		const record = charlie.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.settledHtlcs).to.have.length(2);
		const credited = localBalanceMsat(charlie, charlieChannelId) - before;
		expect(credited).to.equal(INVOICE_MSAT - SKIM_MSAT);
		expect(record.amountMsat).to.equal(INVOICE_MSAT);
		expect(record.receivedMsat).to.equal(credited);
	});

	it('still refuses a second part skimmed for the fee the first already took', async () => {
		const { chain } = chainOnStorage(30);
		const { charlie } = chain;
		const invoice = charlie.createInvoice({
			amountMsat: INVOICE_MSAT,
			description: 'jit skim twice',
			jitFeeAllowance: JIT_FEE
		});
		const actions: string[] = [];
		charlie.on('log', (log: { action: string }) => actions.push(log.action));
		skimForwards(chain.bob, invoice.paymentHash, [SKIM_MSAT, SKIM_MSAT]);

		await payInHalves(chain, invoice);
		await waitUntil(
			() => actions.includes('final_incorrect_htlc_amount'),
			'the second part to be refused'
		);

		const record = charlie.getPayment(invoice.paymentHash)!;
		expect(record.status, 'the set never completes').to.equal(
			PaymentStatus.PENDING
		);
		expect(record.receivedMsat).to.equal(undefined);
		expect(heldParts(charlie, invoice.paymentHash)).to.equal(1);
	});

	it('an amount-less skim records the declared amount and the credited one', async () => {
		const { chain } = chainOnStorage(40);
		const { charlie, charlieChannelId } = chain;
		const invoice = charlie.createInvoice({
			description: 'jit skim any amount',
			jitFeeAllowance: JIT_FEE
		});
		skimForwards(chain.bob, invoice.paymentHash, [SKIM_MSAT]);
		const before = localBalanceMsat(charlie, charlieChannelId);

		expect(await payWhole(chain, invoice)).to.equal(PaymentStatus.COMPLETED);

		const record = charlie.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.amountMsat).to.equal(INVOICE_MSAT);
		expect(record.receivedMsat).to.equal(
			localBalanceMsat(charlie, charlieChannelId) - before
		);
	});

	it('a payment settled in full carries no receivedMsat', async () => {
		const { chain } = chainOnStorage(50);
		const { charlie } = chain;
		const invoice = charlie.createInvoice({
			amountMsat: INVOICE_MSAT,
			description: 'no skim',
			jitFeeAllowance: JIT_FEE
		});
		expect(await payWhole(chain, invoice)).to.equal(PaymentStatus.COMPLETED);
		const record = charlie.getPayment(invoice.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.amountMsat).to.equal(INVOICE_MSAT);
		expect('receivedMsat' in record).to.equal(false);
	});

	it('round-trips receivedMsat through the payment row, and omits it when absent', () => {
		const record: IPaymentInfo = {
			paymentHash: crypto.randomBytes(32),
			amountMsat: INVOICE_MSAT,
			receivedMsat: INVOICE_MSAT - SKIM_MSAT,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.INCOMING,
			createdAt: 1
		};
		const row = serializePaymentInfo(record);
		expect(row.receivedMsat).to.equal('19880000');
		expect(deserializePaymentInfo(row).receivedMsat).to.equal(
			INVOICE_MSAT - SKIM_MSAT
		);
		const plain = serializePaymentInfo({ ...record, receivedMsat: undefined });
		expect('receivedMsat' in plain).to.equal(false);
		expect('receivedMsat' in deserializePaymentInfo(plain)).to.equal(false);
	});
});
