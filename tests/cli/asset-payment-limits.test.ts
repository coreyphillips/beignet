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
 *
 * An asset payment sent in parts (issue #2098, step 9) is judged whole: see
 * the second suite, whose own header says how.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AsyncSpendClaim, BeignetNode } from '../../src/cli/beignet-node';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import type { IAuxiliaryFundingDescriptor } from '../../src/lightning/channel/auxiliary-funding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	AuxiliaryPaymentError,
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	RECEIVE_IN_PARTS,
	SEND_IN_PARTS,
	assetHost,
	openAssetChannel,
	turns,
	withAssetOpens,
	withAssetPartsReceived,
	withAssetPartsSent,
	type IAssetHost
} from '../lightning/helpers/auxiliary-nodes';
import {
	amountRecord,
	referenceProvider
} from '../lightning/helpers/auxiliary-pair';
import { connectNodes } from '../lightning/helpers/loopback-nodes';

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

/**
 * Issue #2098, step 9: an asset payment sent in parts, one
 * sendPaymentToRoute per part, each asked of the gate with the total the
 * part declares (`totalMsat`) and the id its HTLC will take (`htlcId`). The
 * daemon judges the payment whole:
 *
 * - each part opens a claim of its own under the hash, tied to the part
 *   (`<channel hex>:offered-<id>`), at what leaves the node for it;
 * - the per-payment limit is judged on the claims of the parts in flight
 *   together with the new part's, and the daily limit as before;
 * - a part that fails, or that its channel refuses at the add, gives its
 *   own claim back;
 * - the settle charges the day the claims of the parts that did not fail,
 *   live and at the boot reconciliation alike, as one figure;
 * - payment:failed gives every claim back once nothing is in flight, as
 *   before, and a host without the opt-in is admitted and charged as before.
 *
 * Most cases ask the gate the daemon set on its node directly, and play the
 * engine's listing of the parts (getAuxiliaryPaymentHtlcs) and its events
 * back to the daemon. Two send real HTLCs over a real asset channel to a
 * peer that takes them, and settle the engine's own records: one from a
 * host with the opt-in, in two parts, and one from a host without it, in
 * one HTLC, which is admitted and charged as before.
 *
 * Written first: on a build before step 9 the gate is asked about each call
 * alone and ties a claim to nothing, and the engine refuses a part.
 */

/** A second asset channel of the same peer. */
const CHANNEL_B = Buffer.alloc(32, 0xc5);

/** The bitcoin each asset HTLC of these cases carries on the wire. */
const CARRIER_MSAT = 354_000n;

/** What the daemon logs when a settle is charged above its claim. */
const ABOVE_RESERVATION =
	'Payment settled above its reservation; charged in full';

/** A part as the gate is asked about it and as the engine lists it. */
interface IPart {
	channelId: Buffer;
	htlcId: bigint;
	/** What the part is worth at its destination: its final hop's amount. */
	valueMsat: bigint;
	/** What its route asks the first hop to carry. */
	routeMsat: bigint;
	/** The bitcoin its HTLC carries. */
	wireMsat: bigint;
	failed?: boolean;
	/** Fulfilled: no longer in its channel, and not failed. */
	settled?: boolean;
}

/** A part worth `valueMsat`, whose route pays `feeMsat` on top, with the carrier. */
const partOf = (
	channelId: Buffer,
	htlcId: bigint,
	valueMsat: bigint,
	feeMsat = 0n
): IPart => ({
	channelId,
	htlcId,
	valueMsat,
	routeMsat: valueMsat + feeMsat,
	wireMsat: CARRIER_MSAT
});

/** The part a claim is tied to, as the daemon names it. */
const partKey = (part: { channelId: Buffer; htlcId: bigint }): string =>
	`${part.channelId.toString('hex')}:offered-${part.htlcId}`;

/** A claim, with the part it is tied to where it is tied to one. */
type PartClaim = AsyncSpendClaim & { part?: string };

type PartsEngine = Engine & {
	getAuxiliaryPaymentHtlcs: (paymentHash: Buffer) => unknown[];
};

/** The gate as the daemon set it on its node, asked with any fields. */
type PartsGate = (
	payment: Record<string, unknown>
) => string | { reason?: string; message: string } | undefined;

type Refusal = { reason?: string; message: string } | undefined;

type Logged = {
	level: string;
	message: string;
	data?: Record<string, unknown>;
};

type LogMethod = (
	this: BeignetNode,
	level: string,
	message: string,
	data?: Record<string, unknown>
) => void;

/** What a host values an asset HTLC at: each unit a satoshi. */
const worth = (context: { auxiliaryAmount?: bigint }): bigint | undefined =>
	context.auxiliaryAmount === undefined
		? undefined
		: context.auxiliaryAmount * 1000n;

/** What a peer that runs asset channels advertises in its init. */
const assetPeerFeatures = (): FeatureFlags => {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	flags.setOptional(Feature.OPTION_TAPROOT);
	flags.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
	return flags;
};

/**
 * An extension that supplies asset channels, as a host that sends in parts
 * does (`sendInParts: true`) unless `optIn` is false. `incoming` holds the
 * asset openings the node accepts.
 */
const partsAssets = (
	optIn: boolean,
	incoming = new Map<string, IAuxiliaryFundingDescriptor>()
): IBeignetExtension => ({
	id: 'assets',
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach: () => ({
		auxiliaryChannels: {
			provider: referenceProvider(),
			allowLegacyHtlcSignatures: (): boolean => true,
			resolveIncoming: (_peer, id) => incoming.get(id.toString('hex')),
			valueIncomingHtlc: worth,
			...(optIn ? SEND_IN_PARTS : {})
		}
	})
});

const engineOf = (of: BeignetNode): PartsEngine =>
	of.getNode() as unknown as PartsEngine;
const claimsOf = (of: BeignetNode, paymentHash: Buffer): PartClaim[] =>
	(of as unknown as Internals)._asyncSpendClaims.get(
		paymentHash.toString('hex')
	) ?? [];
/** The parts whose claims still hold budget, by the part each is tied to. */
const reservedParts = (
	of: BeignetNode,
	paymentHash: Buffer
): Array<string | undefined> =>
	claimsOf(of, paymentHash)
		.filter((claim) => claim.reserved)
		.map((claim) => claim.part);
/** What the claims of a hash that still hold budget hold, in sats. */
const reservedSats = (of: BeignetNode, paymentHash: Buffer): number[] =>
	claimsOf(of, paymentHash)
		.filter((claim) => claim.reserved)
		.map((claim) => claim.sats);
const pendingOf = (of: BeignetNode): number =>
	(of as unknown as Internals)._pendingSpendSats;
const spentOf = (of: BeignetNode): number => of.getDailySpendInfo().spentSats;
const sha256 = (data: Buffer): Buffer =>
	crypto.createHash('sha256').update(data).digest();

/** Every line the daemon logs from now on, whatever its log level lets out. */
const logsOf = (of: BeignetNode): Logged[] => {
	const lines: Logged[] = [];
	const target = of as unknown as { log: LogMethod };
	const original = target.log;
	target.log = function (this: BeignetNode, level, message, data): void {
		lines.push({ level, message, data });
		original.call(of, level, message, data);
	};
	return lines;
};

/** A daemon booted by `boot`, with every line logged while it booted. */
const bootLogged = async (
	boot: () => Promise<BeignetNode>
): Promise<{ node: BeignetNode; lines: Logged[] }> => {
	const prototype = BeignetNode.prototype as unknown as { log: LogMethod };
	const original = prototype.log;
	const lines: Logged[] = [];
	prototype.log = function (this: BeignetNode, level, message, data): void {
		lines.push({ level, message, data });
		original.call(this, level, message, data);
	};
	try {
		return { node: await boot(), lines };
	} finally {
		prototype.log = original;
	}
};

describe('An asset payment sent in parts is admitted and charged as one payment (#2098, step 9)', function () {
	this.timeout(60_000);
	withAssetOpens();
	withAssetPartsSent();
	withAssetPartsReceived();

	const closers: Array<() => Promise<void>> = [];
	afterEach(async () => {
		for (const close of closers.splice(0).reverse()) await close();
	});

	describe('with the engine played back to the daemon', () => {
		let daemon: BeignetNode;
		/** The parts the engine lists, by hash hex, in the order sent. */
		let listed: Map<string, IPart[]>;

		/** A part as getAuxiliaryPaymentHtlcs lists it. */
		const listingOf = (
			paymentHash: Buffer,
			part: IPart
		): Record<string, unknown> => ({
			channelId: Buffer.from(part.channelId),
			htlcId: part.htlcId,
			amountMsat: part.valueMsat,
			routeAmountMsat: part.routeMsat,
			wireAmountMsat: part.wireMsat,
			...(part.failed
				? { failed: true }
				: part.settled
				? {}
				: {
						htlc: {
							htlcId: part.htlcId,
							direction: 'offered',
							paymentHash: Buffer.from(paymentHash),
							wireAmountMsat: part.wireMsat,
							cltvExpiry: 140,
							auxiliaryAmount: part.valueMsat / 1000n,
							customRecords: amountRecord(part.valueMsat / 1000n)
						}
				  })
		});

		/**
		 * The engine's record of a payment in parts, as the listing has its
		 * parts: the carriers and the values of the parts not failed (of all
		 * of them once every one has), the first part's channel, and the
		 * route of the first part with the totals a host's route carries.
		 */
		const recordOf = (
			paymentHash: Buffer,
			status: PaymentStatus,
			more: Partial<IPaymentInfo> = {}
		): IPaymentInfo => {
			const parts = listed.get(paymentHash.toString('hex')) ?? [];
			const live = parts.filter((part) => !part.failed);
			const counted = live.length > 0 ? live : parts;
			const [first] = parts;
			return {
				paymentHash,
				amountMsat: counted.reduce((sum, part) => sum + part.wireMsat, 0n),
				auxiliary: true,
				auxiliaryValueMsat: counted.reduce(
					(sum, part) => sum + part.valueMsat,
					0n
				),
				direction: PaymentDirection.OUTGOING,
				status,
				createdAt: Date.now(),
				route: {
					...routeOf(first.routeMsat, first.valueMsat),
					totalAmountMsat: first.routeMsat,
					totalFeeMsat: first.routeMsat - first.valueMsat,
					totalCltvDelta: 120
				},
				metadata: {
					_auxiliaryChannelId: first.channelId.toString('hex'),
					_auxiliaryWireAmountMsat: first.wireMsat.toString(),
					_auxiliaryPartAmounts: JSON.stringify(
						Object.fromEntries(
							parts.map((part) => [partKey(part), part.valueMsat.toString()])
						)
					),
					// Each part as the engine records it before it is sent: its
					// first hop, its carrier, its set, and whether it failed.
					_auxiliaryPartsSent: JSON.stringify(
						Object.fromEntries(
							parts.map((part) => [
								partKey(part),
								{
									route: part.routeMsat.toString(),
									wire: part.wireMsat.toString(),
									set: 1,
									...(part.failed ? { failed: true } : {})
								}
							])
						)
					)
				},
				...more
			} as IPaymentInfo;
		};

		/**
		 * The node of `of` lists the parts of `listed`, and has in flight for
		 * a hash the parts of it that have not failed.
		 */
		const playBack = (of: BeignetNode): void => {
			const node = engineOf(of);
			node.hasHtlcInFlight = (paymentHash: Buffer): boolean =>
				(listed.get(paymentHash.toString('hex')) ?? []).some(
					(part) => !part.failed && !part.settled
				);
			node.getAuxiliaryPaymentHtlcs = (paymentHash: Buffer): unknown[] =>
				(listed.get(paymentHash.toString('hex')) ?? []).map((part) =>
					listingOf(paymentHash, part)
				);
		};

		/** The gate of `of` asked about a part of a payment of `totalMsat`. */
		const ask = (
			of: BeignetNode,
			paymentHash: Buffer,
			part: IPart,
			totalMsat: bigint
		): Refusal => {
			const gate = engineOf(of).auxiliaryPaymentGate as PartsGate;
			const answer = gate({
				paymentHash: Buffer.from(paymentHash),
				channelId: Buffer.from(part.channelId),
				amountMsat: part.valueMsat,
				wireAmountMsat: part.wireMsat,
				routeAmountMsat: part.routeMsat,
				totalMsat,
				htlcId: part.htlcId
			});
			return typeof answer === 'string' ? { message: answer } : answer;
		};

		/**
		 * The host sends a part. The gate is asked, and a part it lets
		 * through is then recorded, listed and in flight, as the engine has
		 * it once the send returns. Returns the gate's refusal.
		 */
		const sendPart = (
			of: BeignetNode,
			paymentHash: Buffer,
			part: IPart,
			totalMsat: bigint
		): Refusal => {
			const refusal = ask(of, paymentHash, part, totalMsat);
			if (refusal) return refusal;
			const hex = paymentHash.toString('hex');
			listed.set(hex, [...(listed.get(hex) ?? []), part]);
			engineOf(of).payments.set(
				hex,
				recordOf(paymentHash, PaymentStatus.PENDING)
			);
			return undefined;
		};

		/**
		 * A part fails back off the chain while another is in flight: the
		 * listing marks it failed, the record stays PENDING, and the engine
		 * tells of the HTLC's end.
		 */
		const failPart = (
			of: BeignetNode,
			paymentHash: Buffer,
			part: IPart
		): void => {
			part.failed = true;
			engineOf(of).payments.set(
				paymentHash.toString('hex'),
				recordOf(paymentHash, PaymentStatus.PENDING)
			);
			engineOf(of).emit('payment:htlc-resolved', {
				paymentHash: Buffer.from(paymentHash),
				channelId: Buffer.from(part.channelId),
				htlcId: part.htlcId,
				state: 'failed'
			});
		};

		const freshHash = (): Buffer => crypto.randomBytes(32);

		/**
		 * The payee settles: every part of the hash not failed is fulfilled,
		 * the record is COMPLETED, and the engine reports it.
		 */
		const settleParts = (of: BeignetNode, paymentHash: Buffer): void => {
			for (const part of listed.get(paymentHash.toString('hex')) ?? []) {
				if (!part.failed) part.settled = true;
			}
			const record = recordOf(paymentHash, PaymentStatus.COMPLETED, {
				completedAt: Date.now()
			});
			engineOf(of).payments.set(paymentHash.toString('hex'), record);
			engineOf(of).emit('payment:sent', record);
		};

		beforeEach(async () => {
			listed = new Map();
			daemon = await BeignetNode.create({
				...BOOT,
				storage: new MemoryStorage(),
				dailySpendLimitSats: 10_000,
				maxPaymentSats: 5_000,
				extensions: [partsAssets(true)]
			});
			playBack(daemon);
		});

		afterEach(async () => {
			await daemon?.destroy();
		});

		it('opens a claim of its own for each part under the hash, tied to the part, at what leaves the node for it rounded up', async () => {
			const paymentHash = freshHash();
			// Over two asset channels of one peer. The first part's route
			// carries 3,000.5 sats for a part worth 2,990.5; the second part
			// is worth less than the bitcoin its HTLC carries.
			const first = partOf(CHANNEL, 0n, 2_990_500n, 10_000n);
			const second = partOf(CHANNEL_B, 3n, 100_000n);
			const totalMsat = 3_090_500n;
			expect(sendPart(daemon, paymentHash, first, totalMsat)).to.equal(
				undefined
			);
			expect(sendPart(daemon, paymentHash, second, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			expect(
				claimsOf(daemon, paymentHash).map((claim) => [
					claim.sats,
					claim.part,
					claim.reserved
				])
			).to.deep.equal([
				[3_001, partKey(first), true],
				[354, partKey(second), true]
			]);
			expect(pendingOf(daemon)).to.equal(3_355);
			expect(spentOf(daemon)).to.equal(0);
		});

		it('refuses a part once the parts in flight and it together pass the per-payment limit, and holds nothing for it', async () => {
			const paymentHash = freshHash();
			const totalMsat = 5_100_000n;
			const first = partOf(CHANNEL, 0n, 3_000_000n, 10_000n);
			expect(sendPart(daemon, paymentHash, first, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			// 3,010 sats and 2,000 sats: 5,010 for one payment, where the
			// limit is 5,000. Each alone is within it.
			const over = sendPart(
				daemon,
				paymentHash,
				partOf(CHANNEL_B, 0n, 1_990_000n, 10_000n),
				totalMsat
			);
			expect(over?.reason).to.equal('SPENDING_LIMIT_EXCEEDED');
			expect(over?.message).to.match(/per-payment limit of 5000 sats/);
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first)
			]);
			expect(claimsOf(daemon, paymentHash)).to.have.length(1);
			expect(pendingOf(daemon)).to.equal(3_010);

			// A part that brings the payment to the limit exactly goes through.
			const fits = partOf(CHANNEL_B, 0n, 1_980_000n, 10_000n);
			expect(sendPart(daemon, paymentHash, fits, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first),
				partKey(fits)
			]);
			expect(pendingOf(daemon)).to.equal(5_000);
		});

		it("gives a failed part's claim back when the engine reports the part failed, admits the part sent again near the daily limit, and charges the settle without the failed part", async () => {
			// Another payment holds 4,500 sats of the day's 10,000.
			const other = freshHash();
			expect(
				sendPart(daemon, other, partOf(CHANNEL_B, 5n, 4_500_000n), 4_500_000n)
			).to.equal(undefined);
			const paymentHash = freshHash();
			const totalMsat = 4_500_000n;
			const first = partOf(CHANNEL, 0n, 2_000_000n);
			const second = partOf(CHANNEL, 1n, 2_500_000n);
			expect(sendPart(daemon, paymentHash, first, totalMsat)).to.equal(
				undefined
			);
			expect(sendPart(daemon, paymentHash, second, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			expect(pendingOf(daemon)).to.equal(9_000);

			// The second part fails back while the first is still out.
			failPart(daemon, paymentHash, second);
			expect(
				pendingOf(daemon),
				"the failed part's claim is given back"
			).to.equal(6_500);
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first)
			]);

			// Sent again over the other channel: 6,500 and 2,500 sats are
			// 9,000 of the day, and the payment's parts in flight 4,500. Were
			// the failed part's claim still held, the day would be passed.
			const again = partOf(CHANNEL_B, 6n, 2_500_000n);
			expect(sendPart(daemon, paymentHash, again, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first),
				partKey(again)
			]);
			expect(pendingOf(daemon)).to.equal(9_000);
			expect(spentOf(daemon)).to.equal(0);

			// The payee settles: the day is charged the claims of the two
			// parts that did not fail, and the other payment's stays held.
			const lines = logsOf(daemon);
			settleParts(daemon, paymentHash);
			expect(spentOf(daemon)).to.equal(4_500);
			expect(pendingOf(daemon)).to.equal(4_500);
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([]);
			expect(
				lines.filter((line) => line.message === ABOVE_RESERVATION)
			).to.deep.equal([]);
		});

		it('gives back the claim of a part its channel refused at the add while the other part stays in flight, and charges the settle without it when the part sent again takes its id', async () => {
			const paymentHash = freshHash();
			const totalMsat = 4_500_000n;
			const first = partOf(CHANNEL, 0n, 2_000_000n);
			expect(sendPart(daemon, paymentHash, first, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			// The gate lets the second part through. Its channel then refuses
			// it at the add: the send throws, the part is not listed, and the
			// record stays PENDING for the first part.
			const refused = partOf(CHANNEL_B, 0n, 2_500_000n);
			expect(ask(daemon, paymentHash, refused, totalMsat)).to.equal(undefined);
			expect(pendingOf(daemon)).to.equal(4_500);
			await nextMicrotask();
			expect(
				pendingOf(daemon),
				"the refused part's claim is given back once the send has returned"
			).to.equal(2_000);
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first)
			]);
			expect(spentOf(daemon)).to.equal(0);

			// The host sends it again on the same channel, whose next id the
			// refusal did not use up: the part takes that id. The payment's
			// parts in flight are 4,500 sats, within the limit of 5,000.
			const again = partOf(CHANNEL_B, 0n, 2_500_000n);
			expect(sendPart(daemon, paymentHash, again, totalMsat)).to.equal(
				undefined
			);
			await nextMicrotask();
			expect(pendingOf(daemon)).to.equal(4_500);
			expect(reservedParts(daemon, paymentHash)).to.deep.equal([
				partKey(first),
				partKey(again)
			]);

			// The payee settles: the day is charged the two parts that went
			// out, and not the one refused.
			settleParts(daemon, paymentHash);
			expect(spentOf(daemon)).to.equal(4_500);
			expect(pendingOf(daemon)).to.equal(0);
		});

		it('keeps every claim of a payment in parts at payment:failed while a part is in flight, and gives them all back once nothing is', async () => {
			const paymentHash = freshHash();
			const totalMsat = 4_500_000n;
			const first = partOf(CHANNEL, 0n, 2_000_000n);
			const second = partOf(CHANNEL_B, 0n, 2_500_000n);
			for (const part of [first, second]) {
				expect(sendPart(daemon, paymentHash, part, totalMsat)).to.equal(
					undefined
				);
			}
			await nextMicrotask();
			expect(pendingOf(daemon)).to.equal(4_500);

			// The payment is cancelled with both parts out: it fails whole,
			// and neither part can be taken back.
			const failed = recordOf(paymentHash, PaymentStatus.FAILED);
			engineOf(daemon).payments.set(paymentHash.toString('hex'), failed);
			engineOf(daemon).emit('payment:failed', failed);
			expect(reservedSats(daemon, paymentHash)).to.deep.equal([2_000, 2_500]);
			expect(pendingOf(daemon)).to.equal(4_500);

			// Both parts fail back, and the engine gives up with nothing out.
			first.failed = true;
			second.failed = true;
			engineOf(daemon).emit('payment:failed', failed);
			expect(reservedSats(daemon, paymentHash)).to.deep.equal([]);
			expect(pendingOf(daemon)).to.equal(0);
			expect(spentOf(daemon)).to.equal(0);
		});

		it('charges at boot a payment in parts that settled while the daemon was down, at the claims of both parts, logging no settle above a reservation', async () => {
			const dataDir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'beignet-asset-parts-boot-')
			);
			closers.push(async () =>
				fs.rmSync(dataDir, { recursive: true, force: true })
			);
			const boot = (): Promise<BeignetNode> =>
				BeignetNode.create({
					...BOOT,
					dataDir,
					dailySpendLimitSats: 10_000,
					maxPaymentSats: 5_000,
					extensions: [partsAssets(true)]
				});
			const before = await boot();
			let down = false;
			closers.push(async () => {
				if (!down) await before.destroy();
			});
			playBack(before);
			const preimage = crypto.randomBytes(32);
			const paymentHash = sha256(preimage);
			const totalMsat = 4_500_000n;
			for (const part of [
				partOf(CHANNEL, 0n, 2_000_000n),
				partOf(CHANNEL_B, 0n, 2_500_000n)
			]) {
				expect(sendPart(before, paymentHash, part, totalMsat)).to.equal(
					undefined
				);
			}
			await nextMicrotask();
			expect(pendingOf(before)).to.equal(4_500);

			// Both parts were fulfilled and the engine wrote its record
			// COMPLETED; the daemon stopped before it charged the day.
			(
				before as unknown as {
					storage: { savePayment: (hex: string, info: IPaymentInfo) => void };
				}
			).storage.savePayment(
				paymentHash.toString('hex'),
				recordOf(paymentHash, PaymentStatus.COMPLETED, {
					preimage,
					completedAt: Date.now()
				})
			);
			down = true;
			await before.destroy();

			const { node: after, lines } = await bootLogged(boot);
			closers.push(() => after.destroy());
			expect(spentOf(after)).to.equal(4_500);
			expect(after.getDailySpendInfo().lightningSats).to.equal(4_500);
			expect(pendingOf(after)).to.equal(0);
			expect(reservedParts(after, paymentHash)).to.deep.equal([]);
			expect(
				lines.filter((line) => line.message === ABOVE_RESERVATION)
			).to.deep.equal([]);
		});
	});

	describe("over a real asset channel, settling the engine's own records", () => {
		interface IPaidWorld {
			daemon: BeignetNode;
			payee: IAssetHost;
			channelId: Buffer;
			/** Each request the gate was asked, and the hash's claims once it answered. */
			asked: Array<{
				request: Record<string, unknown>;
				claims: PartClaim[];
			}>;
			/** Every line the daemon logged once the channel was open. */
			lines: Logged[];
			/** Stops the daemon, as a process that stops; once. */
			stop(): Promise<void>;
		}

		/** The daemon of a paid world, booted as `paidWorld` boots it. */
		const bootPaid = (
			optIn: boolean,
			dataDir?: string,
			incoming = new Map<string, IAuxiliaryFundingDescriptor>()
		): Promise<BeignetNode> =>
			BeignetNode.create({
				...BOOT,
				...(dataDir ? { dataDir } : { storage: new MemoryStorage() }),
				dailySpendLimitSats: 10_000,
				maxPaymentSats: 5_000,
				extensions: [partsAssets(optIn, incoming)]
			});

		/**
		 * A daemon whose node holds an asset channel with a peer that values
		 * each unit at a satoshi and takes an asset invoice in parts. The
		 * daemon opened the channel and holds 9,000 units on it. Its node is
		 * joined to the peer over a loopback in place of its transport.
		 */
		const paidWorld = async (
			tag: string,
			optIn: boolean,
			/** A data directory in place of memory, so a later daemon boots from it. */
			dataDir?: string
		): Promise<IPaidWorld> => {
			const incoming = new Map<string, IAuxiliaryFundingDescriptor>();
			const daemon = await bootPaid(optIn, dataDir, incoming);
			const node = daemon.getNode();
			// With no peer manager the node hands every message to
			// 'message:outbound', as the loopback nodes of the engine tests do.
			const wired = node as unknown as {
				peerManager: unknown;
				channelManager: { peerManager: unknown };
			};
			const transport = [wired.peerManager, wired.channelManager.peerManager];
			wired.peerManager = null;
			wired.channelManager.peerManager = null;
			const payee = assetHost(tag, 2, {
				valueIncomingHtlc: worth,
				...RECEIVE_IN_PARTS
			});
			let stopped = false;
			const stop = async (): Promise<void> => {
				if (stopped) return;
				stopped = true;
				[wired.peerManager, wired.channelManager.peerManager] = transport;
				await daemon.destroy();
			};
			closers.push(async () => {
				payee.node.destroy();
				await stop();
			});
			// A node opens no channel before it knows the chain tip, and this
			// one has no chain to ask. The loopback exchanges no init, so the
			// node is told what its peer advertises.
			node.handleNewBlock(1);
			(
				node as unknown as { peerInitFeatures: () => FeatureFlags }
			).peerInitFeatures = assetPeerFeatures;
			const errors: string[] = [];
			node.on('node:error', (error: { code?: string; message?: string }) => {
				errors.push(`${error.code ?? ''}: ${error.message ?? ''}`);
			});
			connectNodes(node, payee.node);
			const channelId = await openAssetChannel(
				{ node, incoming, broadcasts: [], errors },
				payee,
				{ tag, openerUnits: 9000n, acceptorUnits: 1000n }
			);
			const engine = engineOf(daemon);
			const gate = engine.auxiliaryPaymentGate as PartsGate;
			const asked: IPaidWorld['asked'] = [];
			engine.auxiliaryPaymentGate = (
				request: Record<string, unknown>
			): ReturnType<PartsGate> => {
				const answer = gate(request);
				asked.push({
					request,
					claims: claimsOf(daemon, request.paymentHash as Buffer).map(
						(claim) => ({ ...claim })
					)
				});
				return answer;
			};
			return {
				daemon,
				payee,
				channelId,
				asked,
				lines: logsOf(daemon),
				stop
			};
		};

		/**
		 * The daemon's node pays `units` of `invoice` over the asset channel
		 * by one HTLC: a part of a payment of `totalMsat` when that is given.
		 * The route carries its totals, as a host's does. Returns what the
		 * send threw.
		 */
		const payUnits = (
			world: IPaidWorld,
			invoice: { paymentHash: Buffer; paymentSecret: Buffer },
			units: bigint,
			totalMsat?: bigint
		): unknown => {
			const valueMsat = units * 1000n;
			try {
				world.daemon.getNode().sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: Buffer.from(world.payee.node.getNodeId(), 'hex'),
								shortChannelId: Buffer.alloc(8, 9),
								amountToForwardMsat: valueMsat,
								outgoingCltvValue: 40
							}
						],
						totalAmountMsat: valueMsat,
						totalFeeMsat: 0n,
						totalCltvDelta: 40
					} as Parameters<LightningNode['sendPaymentToRoute']>[0],
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					totalMsat,
					undefined,
					undefined,
					undefined,
					{
						assetPayment: {
							channelId: world.channelId,
							wireAmountMsat: CARRIER_MSAT,
							customRecords: amountRecord(units)
						}
					}
				);
			} catch (err) {
				return err;
			}
			return undefined;
		};

		it('admits each of two real parts with a claim tied to it, and charges the day both claims when the payee settles, logging no settle above a reservation', async () => {
			const world = await paidWorld('limits-parts-settle', true);
			const invoice = world.payee.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'units paid in two parts'
			});
			expect(
				payUnits(world, invoice, 3000n, 5_000_000n),
				'the first part is sent'
			).to.equal(undefined);
			expect(
				payUnits(world, invoice, 2000n, 5_000_000n),
				'the second part is sent'
			).to.equal(undefined);
			await turns(200);

			const node = world.daemon.getNode();
			expect(
				node.getPayment(invoice.paymentHash)?.status,
				'the payee settled the payment'
			).to.equal(PaymentStatus.COMPLETED);
			const sent = node.getAuxiliaryPaymentHtlcs(invoice.paymentHash);
			expect(sent.map((htlc) => htlc.amountMsat)).to.deep.equal([
				3_000_000n,
				2_000_000n
			]);
			// Each part was asked of the gate with the total it declares and
			// the id its HTLC took, and held a claim of its own, tied to it.
			expect(
				world.asked.map(({ request }) => [request.totalMsat, request.htlcId])
			).to.deep.equal(sent.map((htlc) => [5_000_000n, htlc.htlcId]));
			expect(
				world.asked[1].claims.map((claim) => [
					claim.sats,
					claim.part,
					claim.reserved
				])
			).to.deep.equal([
				[3_000, partKey(sent[0]), true],
				[2_000, partKey(sent[1]), true]
			]);
			// The settle charged the day both claims, as one figure.
			expect(spentOf(world.daemon)).to.equal(5_000);
			expect(world.daemon.getDailySpendInfo().lightningSats).to.equal(5_000);
			expect(pendingOf(world.daemon)).to.equal(0);
			expect(reservedParts(world.daemon, invoice.paymentHash)).to.deep.equal(
				[]
			);
			expect(
				world.lines.filter((line) => line.message === ABOVE_RESERVATION)
			).to.deep.equal([]);
		});

		it('charges at boot the claims of both parts of a real payment in parts whose settle the daemon did not hear before it stopped', async () => {
			const dataDir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'beignet-asset-parts-real-boot-')
			);
			closers.push(async () =>
				fs.rmSync(dataDir, { recursive: true, force: true })
			);
			const world = await paidWorld('limits-parts-boot', true, dataDir);
			// The engine settles the payment, and the daemon does not hear of
			// it: it stops between the engine's write and its own charge.
			(
				world.daemon.getNode() as unknown as {
					removeAllListeners: (event: string) => void;
				}
			).removeAllListeners('payment:sent');
			const invoice = world.payee.node.createInvoice({
				amountMsat: 5_000_000n,
				description: 'units paid in two parts, settled unheard'
			});
			expect(
				payUnits(world, invoice, 3000n, 5_000_000n),
				'the first part is sent'
			).to.equal(undefined);
			expect(
				payUnits(world, invoice, 2000n, 5_000_000n),
				'the second part is sent'
			).to.equal(undefined);
			await turns(200);
			expect(
				world.daemon.getNode().getPayment(invoice.paymentHash)?.status,
				'the payee settled the payment'
			).to.equal(PaymentStatus.COMPLETED);
			expect(spentOf(world.daemon), 'nothing was charged live').to.equal(0);
			expect(
				claimsOf(world.daemon, invoice.paymentHash).filter(
					(claim) => !claim.settled
				),
				'the claims wait in the ledger'
			).to.have.length(2);
			await world.stop();

			const { node: after, lines } = await bootLogged(() =>
				bootPaid(true, dataDir)
			);
			closers.push(() => after.destroy());
			expect(spentOf(after)).to.equal(5_000);
			expect(after.getDailySpendInfo().lightningSats).to.equal(5_000);
			expect(pendingOf(after)).to.equal(0);
			expect(reservedParts(after, invoice.paymentHash)).to.deep.equal([]);
			expect(
				lines.filter((line) => line.message === ABOVE_RESERVATION)
			).to.deep.equal([]);
		});

		it('admits and charges a payment of one HTLC from a host without the opt-in as before, and refuses a part from it with nothing held', async () => {
			const world = await paidWorld('limits-parts-plain', false);
			const invoice = world.payee.node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'units paid whole'
			});
			expect(payUnits(world, invoice, 3000n), 'the payment is sent').to.equal(
				undefined
			);
			await turns(200);
			expect(
				world.daemon.getNode().getPayment(invoice.paymentHash)?.status,
				'the payee settled the payment'
			).to.equal(PaymentStatus.COMPLETED);
			// The gate was asked what it was always asked, and its claim is
			// tied to no part.
			expect(world.asked).to.have.length(1);
			expect(Object.keys(world.asked[0].request).sort()).to.deep.equal([
				'amountMsat',
				'channelId',
				'paymentHash',
				'routeAmountMsat',
				'wireAmountMsat'
			]);
			expect(
				world.asked[0].claims.map((claim) => [claim.sats, claim.part])
			).to.deep.equal([[3_000, undefined]]);
			expect(spentOf(world.daemon)).to.equal(3_000);
			expect(pendingOf(world.daemon)).to.equal(0);

			// A part from this host is refused, as it always was, and nothing
			// is held for it once the send has returned.
			const part = {
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32)
			};
			const refusal = payUnits(world, part, 1000n, 2_000_000n);
			expect(refusal).to.be.instanceOf(AuxiliaryPaymentError);
			expect((refusal as AuxiliaryPaymentError).code).to.equal(
				'ASSET_PAYMENT_UNSUPPORTED'
			);
			expect((refusal as Error).message).to.equal(
				'An asset payment is made by one HTLC and cannot be a part of a ' +
					`multi-part payment (channel ${world.channelId.toString('hex')})`
			);
			await nextMicrotask();
			expect(reservedParts(world.daemon, part.paymentHash)).to.deep.equal([]);
			expect(world.daemon.getNode().getPayment(part.paymentHash)).to.equal(
				undefined
			);
			expect(pendingOf(world.daemon)).to.equal(0);
			expect(spentOf(world.daemon)).to.equal(3_000);
		});
	});
});
