/**
 * Asset payments and the wallet's spending limits (issue #2093, step 13).
 *
 * An asset payment leaves through the extension that holds the node, not
 * through a route of the daemon, so the daemon sets the node's payment gate
 * and admits each one exactly as sendToRoute admits a route: drain mode,
 * the per-payment and daily limits, and a claim on the daily budget under
 * the payment hash, on what the route asks the first hop to carry. A
 * refusal reaches the sender as the typed ASSET_PAYMENT_REFUSED with the
 * limit's own code in `reason`, and nothing is recorded, sent or claimed.
 *
 * Offline suite, like tests/cli/send-to-route-limits.test.ts: no chain and
 * no channel. The send is the engine's own, so the gate is asked where the
 * engine asks it; what happens to an HTLC afterwards is played back to the
 * daemon as the engine reports it (payment:sent, payment:failed).
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { AsyncSpendClaim, BeignetNode } from '../../src/cli/beignet-node';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	AuxiliaryPaymentError,
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	amountRecord,
	referenceProvider
} from '../lightning/helpers/auxiliary-pair';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const BOOT = {
	mnemonic: MNEMONIC,
	network: 'regtest' as const,
	logLevel: 'silent' as const,
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const HOP = getPublicKey(Buffer.alloc(32, 3));
const DESTINATION = getPublicKey(Buffer.alloc(32, 5));
const CHANNEL = Buffer.alloc(32, 0xc4);

type Engine = {
	payments: Map<string, IPaymentInfo>;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	emit: (event: string, info: unknown) => boolean;
	auxiliaryPaymentGate: unknown;
};

type Internals = {
	_pendingSpendSats: number;
	_asyncSpendClaims: Map<string, AsyncSpendClaim[]>;
};

/** An extension that supplies the node's asset channels, and nothing else. */
const assets = (): IBeignetExtension => ({
	id: 'assets',
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach: () => ({
		auxiliaryChannels: {
			provider: referenceProvider(),
			resolveIncoming: (): undefined => undefined
		}
	})
});

/** A two-hop route: the first hop carries `firstMsat`, the final `finalMsat`. */
const routeOf = (
	firstMsat: bigint,
	finalMsat: bigint
): Parameters<LightningNode['sendPaymentToRoute']>[0] => ({
	hops: [
		{
			pubkey: HOP,
			shortChannelId: Buffer.alloc(8, 1),
			amountToForwardMsat: firstMsat,
			outgoingCltvValue: 80
		},
		{
			pubkey: DESTINATION,
			shortChannelId: Buffer.alloc(8, 2),
			amountToForwardMsat: finalMsat,
			outgoingCltvValue: 40
		}
	]
});

const nextMicrotask = (): Promise<void> => Promise.resolve();

describe('Asset payments are admitted against the spending limits (#2093)', function () {
	this.timeout(60_000);

	let node: BeignetNode;
	let others: BeignetNode[];

	const engine = (of: BeignetNode = node): Engine =>
		of.getNode() as unknown as Engine;
	const internals = (): Internals => node as unknown as Internals;
	const pending = (): number => internals()._pendingSpendSats;
	const spent = (): number => node.getDailySpendInfo().spentSats;
	const claims = (hash: Buffer): AsyncSpendClaim[] =>
		internals()._asyncSpendClaims.get(hash.toString('hex')) ?? [];

	/**
	 * The extension's own send: the engine's sendPaymentToRoute with an asset
	 * payment over a channel. Returns what it threw. With no such channel the
	 * engine refuses the send itself, after the gate has answered.
	 */
	const send = (
		hash: Buffer,
		firstMsat: bigint,
		finalMsat: bigint,
		wireAmountMsat = 354_000n,
		of: BeignetNode = node
	): unknown => {
		try {
			of.getNode().sendPaymentToRoute(
				routeOf(firstMsat, finalMsat),
				hash,
				40,
				Buffer.alloc(32, 9),
				undefined,
				undefined,
				undefined,
				undefined,
				{
					assetPayment: {
						channelId: CHANNEL,
						wireAmountMsat,
						customRecords: amountRecord(50n)
					}
				}
			);
		} catch (err) {
			return err;
		}
		return undefined;
	};

	/** The engine reports what became of the HTLC it sent for `hash`. */
	const report = (
		hash: Buffer,
		event: 'payment:sent' | 'payment:failed',
		sentMsat: bigint
	): void => {
		const record: IPaymentInfo = {
			paymentHash: hash,
			amountMsat: sentMsat,
			direction: PaymentDirection.OUTGOING,
			status:
				event === 'payment:sent'
					? PaymentStatus.COMPLETED
					: PaymentStatus.FAILED,
			createdAt: Date.now(),
			completedAt: Date.now()
		} as IPaymentInfo;
		engine().payments.set(hash.toString('hex'), record);
		engine().emit(event, record);
	};

	const hash = (): Buffer => crypto.randomBytes(32);

	beforeEach(async () => {
		others = [];
		node = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage(),
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			extensions: [assets()]
		});
	});

	afterEach(async () => {
		await node?.destroy();
		for (const other of others) await other.destroy();
	});

	it('sets the gate only on a node that runs asset channels', async () => {
		expect(engine().auxiliaryPaymentGate).to.be.a('function');
		const plain = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage(),
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000
		});
		others.push(plain);
		expect(engine(plain).auxiliaryPaymentGate).to.equal(undefined);
	});

	it('refuses a payment over the per-payment limit by the typed code, with the limit as its reason, and records nothing', () => {
		const paymentHash = hash();
		// 5,001 sats leave for a payment worth 4,990.
		const refusal = send(paymentHash, 5_001_000n, 4_990_000n);
		expect(refusal).to.be.instanceOf(AuxiliaryPaymentError);
		const typed = refusal as AuxiliaryPaymentError;
		expect(typed.code).to.equal('ASSET_PAYMENT_REFUSED');
		expect(typed.reason).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(typed.channelId).to.equal(CHANNEL.toString('hex'));
		expect(typed.message).to.equal(
			'Payment amount 5001 sats exceeds per-payment limit of 5000 sats ' +
				`(channel ${CHANNEL.toString('hex')})`
		);
		expect(node.getNode().getPayment(paymentHash)).to.equal(undefined);
		expect(claims(paymentHash)).to.have.length(0);
		expect(pending()).to.equal(0);
		expect(spent()).to.equal(0);
	});

	it('refuses while the wallet drains, and what is left of the day afterwards', async () => {
		node.setDraining(true);
		const draining = send(hash(), 1_000_000n, 1_000_000n);
		expect((draining as AuxiliaryPaymentError).code).to.equal(
			'ASSET_PAYMENT_REFUSED'
		);
		expect((draining as AuxiliaryPaymentError).reason).to.equal(
			'SERVICE_DRAINING'
		);
		node.setDraining(false);

		// Two payments of 4,000 sats go out and hold the day's budget.
		engine().hasHtlcInFlight = (): boolean => true;
		const first = hash();
		const second = hash();
		send(first, 4_000_000n, 3_990_000n);
		send(second, 4_000_000n, 3_990_000n);
		await nextMicrotask();
		expect(pending()).to.equal(8_000);

		// A third would pass the daily limit: 2,000 remain.
		const third = hash();
		const over = send(third, 2_001_000n, 2_000_000n);
		expect((over as AuxiliaryPaymentError).code).to.equal(
			'ASSET_PAYMENT_REFUSED'
		);
		expect((over as AuxiliaryPaymentError).reason).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		expect((over as Error).message).to.match(
			/^Daily spend limit exceeded\. Limit: 10000 sats, .*remaining: 2000 sats, requested: 2001 sats/
		);
		expect(claims(third)).to.have.length(0);
		expect(pending()).to.equal(8_000);
		expect(node.getDailySpendInfo().pendingSats).to.equal(8_000);
	});

	it('claims the daily budget under the payment hash and is charged what left the node when the payment settles', async () => {
		engine().hasHtlcInFlight = (): boolean => true;
		const paymentHash = hash();
		// The route asks the first hop to carry 3,010 sats for 3,000.
		send(paymentHash, 3_010_000n, 3_000_000n);
		await nextMicrotask();
		expect(claims(paymentHash).map((claim) => claim.sats)).to.deep.equal([
			3_010
		]);
		expect(pending()).to.equal(3_010);
		expect(spent()).to.equal(0);

		report(paymentHash, 'payment:sent', 3_010_000n);
		expect(pending()).to.equal(0);
		expect(spent()).to.equal(3_010);
		expect(node.getDailySpendInfo().lightningSats).to.equal(3_010);
		expect(claims(paymentHash)).to.have.length(0);
	});

	it('gives the budget back when the payment fails with nothing in flight', async () => {
		engine().hasHtlcInFlight = (): boolean => true;
		const paymentHash = hash();
		send(paymentHash, 3_010_000n, 3_000_000n);
		await nextMicrotask();
		expect(pending()).to.equal(3_010);
		engine().hasHtlcInFlight = (): boolean => false;
		report(paymentHash, 'payment:failed', 3_010_000n);
		expect(pending()).to.equal(0);
		expect(spent()).to.equal(0);
	});

	it('holds nothing for a payment the engine refused after the gate let it through', async () => {
		const paymentHash = hash();
		const refusal = send(paymentHash, 3_010_000n, 3_000_000n);
		// The gate admitted it and the engine then found no such channel.
		expect(refusal).to.be.instanceOf(Error);
		expect((refusal as { code?: string }).code).to.not.equal(
			'ASSET_PAYMENT_REFUSED'
		);
		expect(pending()).to.equal(3_010);
		await nextMicrotask();
		expect(pending()).to.equal(0);
		expect(spent()).to.equal(0);
		expect(
			claims(paymentHash).filter((claim) => claim.reserved)
		).to.have.length(0);
	});

	it('admits on the bitcoin the HTLC carries when the route says less', async () => {
		engine().hasHtlcInFlight = (): boolean => true;
		const paymentHash = hash();
		send(paymentHash, 100_000n, 100_000n, 354_000n);
		await nextMicrotask();
		expect(claims(paymentHash).map((claim) => claim.sats)).to.deep.equal([354]);
	});

	it('checks the per-payment limit and claims nothing when no daily limit is set', async () => {
		const unlimited = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage(),
			maxPaymentSats: 5_000,
			extensions: [assets()]
		});
		others.push(unlimited);
		const over = send(hash(), 5_001_000n, 5_000_000n, 354_000n, unlimited);
		expect((over as AuxiliaryPaymentError).reason).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		const under = hash();
		const met = send(under, 4_000_000n, 4_000_000n, 354_000n, unlimited);
		expect((met as { code?: string }).code).to.not.equal(
			'ASSET_PAYMENT_REFUSED'
		);
		expect(
			(unlimited as unknown as Internals)._asyncSpendClaims.get(
				under.toString('hex')
			)
		).to.equal(undefined);
	});
});
