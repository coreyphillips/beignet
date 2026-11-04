/**
 * MPP across distinct first-hop peers (issue #1922, step 3).
 *
 * A wallet W holds channels with several primaries, each of which has a
 * channel to the recipient D. An invoice from D larger than any one W channel's
 * spendable balance, but within their sum, must complete with one part per
 * primary. The splitter already walked every local channel; what failed was
 * its sizing (a halved part left later parts to run out before the amount
 * did) and the four-part default once a wallet holds more channels than that.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	InvalidRequestError,
	PaymentStatus
} from '../../src/lightning/node/types';
import { IRoutingHintHop } from '../../src/lightning/invoice/types';
import {
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianReplicator,
	RecoveryJournal,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { encodedMutationBytes } from '../../src/lightning/recovery/frame-codec';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	FEE_INSUFFICIENT,
	MPP_TIMEOUT,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { encodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';
import { signChannelUpdate } from '../../src/lightning/gossip/validation';
import { MessageType } from '../../src/lightning/message/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { Network } from '../../src/lightning/invoice/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createNode,
	destroyAll,
	nodePrivkey,
	settle,
	waitFor,
	wire
} from './helpers/async-world';
import { writableState } from './helpers/writable-state';

interface IPrimary {
	node: LightningNode;
	/** W's channel with this primary. */
	wChannelId: Buffer;
	/** This primary's channel with D. */
	dChannelId: Buffer;
	/** Adds this primary forwarded to D. */
	forwards: number;
	/** What those adds carried to D. */
	forwardedMsat: bigint;
}

interface IWorld {
	w: LightningNode;
	d: LightningNode;
	primaries: IPrimary[];
	/** update_add_htlc messages W sent, one per part. */
	wAdds: number;
	spendable: bigint[];
	nodes: LightningNode[];
}

async function openChannelOf(
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis: bigint
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), fundingSatoshis);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	return channelId;
}

interface IWorldOptions {
	/** Each primary's channel to D, 1M sats unless given. */
	dChannelSats?: bigint[];
	/**
	 * More W channels with the first primary, after its own: parts over them
	 * share that primary's channel to D. Their spendable balances follow the
	 * primaries' in `spendable`.
	 */
	extraWChannelSats?: bigint[];
	wExtra?: Partial<INodeConfig>;
	dExtra?: Partial<INodeConfig>;
}

/**
 * W opens one channel per entry of `wChannelSats` to a fresh primary, and each
 * primary opens a 1M-sat channel to D (or its `dChannelSats` entry), so D has
 * inbound on every primary and W holds the balance on its side. The P-D
 * channels are private: D's invoice hints them by the alias the primary chose,
 * which the primary forwards over once registered, as the async-world setup
 * does.
 */
async function buildWorld(
	seedBase: number,
	wChannelSats: bigint[],
	options: IWorldOptions = {}
): Promise<IWorld> {
	const w = createNode(seedBase, undefined, options.wExtra);
	const d = createNode(seedBase + 1, undefined, options.dExtra);
	const primaries: IPrimary[] = [];
	for (let i = 0; i < wChannelSats.length; i++) {
		const node = createNode(seedBase + 2 + i);
		wire(w, node, { val: false });
		wire(node, d, { val: false });
		const wChannelId = await openChannelOf(w, node, wChannelSats[i]);
		const dChannelId = await openChannelOf(
			node,
			d,
			options.dChannelSats?.[i] ?? 1_000_000n
		);
		const primary: IPrimary = {
			node,
			wChannelId,
			dChannelId,
			forwards: 0,
			forwardedMsat: 0n
		};
		node.on(
			'htlc:forward',
			(_inChannel: Buffer, _outChannel: Buffer, amountMsat: bigint) => {
				primary.forwards++;
				primary.forwardedMsat += amountMsat;
			}
		);
		primaries.push(primary);
	}
	const extraWChannelIds: Buffer[] = [];
	for (const sats of options.extraWChannelSats ?? []) {
		extraWChannelIds.push(await openChannelOf(w, primaries[0].node, sats));
	}
	const nodes = [w, d, ...primaries.map((p) => p.node)];
	await waitFor(
		() =>
			nodes.every((n) =>
				n
					.getChannelManager()
					.listChannels()
					.every((c) => c.getState() === ChannelState.NORMAL)
			),
		'every channel on every node to reach NORMAL'
	);
	primaries.forEach((p, i) => {
		const scid = hintScidOf(i);
		p.node.registerChannelScid(p.dChannelId, scid);
		writableState(
			p.node.getChannelManager().getChannel(p.dChannelId)!
		).remoteScidAlias = scid;
		writableState(
			d.getChannelManager().getChannel(p.dChannelId)!
		).remoteScidAlias = scid;
	});
	const world: IWorld = {
		w,
		d,
		primaries,
		wAdds: 0,
		spendable: [...primaries.map((p) => p.wChannelId), ...extraWChannelIds].map(
			(id) => w.getChannelManager().getChannel(id)!.getSpendableOutboundMsat()
		),
		nodes
	};
	w.on('message:outbound', (_pk: string, type: number) => {
		if (type === MessageType.UPDATE_ADD_HTLC) world.wAdds++;
	});
	return world;
}

/** The alias primary `i` registers for its channel to D, which D's invoice hints. */
function hintScidOf(i: number): Buffer {
	return encodeShortChannelId({ block: 840, txIndex: i + 1, outputIndex: 0 });
}

/**
 * Make W's planner prefer the other primaries over primary `i` when more than
 * one can carry a part: a MissionControl penalty on the hinted channel adds a
 * cost, not an exclusion, so a replacement part can still take it.
 */
function penalise(world: IWorld, i: number): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(world.w as any).missionControl.recordFailure(hintScidOf(i).toString('hex'));
}

const GUARDIAN_IDS = [1, 2, 3].map((i) =>
	xOnlyFromSecret(
		crypto.createHash('sha256').update(`mpp-guardian-${i}`).digest()
	)
);
const GUARDIAN_SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
let guardianClock = 2_230_000_000_000n;

/**
 * Recovery config whose guardians take records up to `ceiling` bytes. No
 * lease, so nothing is ever sent to them: the journal only learns the limit.
 */
function recoveryUnderCeiling(
	seedId: number,
	storage: MemoryStorage,
	ceiling: number
): INodeConfig['recovery'] {
	const replicator = new GuardianReplicator({
		storage,
		guardians: GUARDIAN_IDS.map((id) => ({
			client: new GuardianClient({
				url: 'http://127.0.0.1:9',
				guardianSetId: GUARDIAN_SET_ID
			}),
			expectedGuardianId: id
		})),
		context: { guardianSetId: GUARDIAN_SET_ID, members: GUARDIAN_IDS },
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: deriveRecoveryRoot(nodePrivkey(seedId)),
		clock: () => ++guardianClock
	});
	replicator.maxRecordBytes = (): number => ceiling;
	return {
		enabled: true,
		durability: 'async-remote',
		barrier: new DurabilityBarrier({
			durability: 'async-remote',
			replicator,
			lease: () => null,
			timeoutMs: 2_000,
			retryDelayMs: 50
		})
	};
}

interface IChainWorld {
	w: LightningNode;
	d: LightningNode;
	/** The four nodes of the long path, Q1 first. */
	chain: LightningNode[];
	nodes: LightningNode[];
	/** update_add_htlc messages W sent, one per part. */
	wAdds: number;
	/** Adds Q1 forwarded down the long path. */
	chainForwards: number;
	/** W's spendable balance with P1, the primary whose part fails. */
	p1Spendable: bigint;
	/** Hints for the long path D's invoices carry. */
	chainHints: IRoutingHintHop[][];
	/** Encoded bytes a payment_state mutation may take in W's frames. */
	room: number;
	/** Encoded bytes of every payment_state W journaled for the hash. */
	rowBytes: (paymentHash: Buffer) => number[];
}

/**
 * W, on a journal whose guardians take records up to `ceiling` bytes, pays D
 * over two primaries and one long path. P1's channel with W carries most of
 * an amount and its channel to D is far too small for it, so P1 fails its
 * part back once P2's has left. P2 has nothing left for the replacement
 * after its own part, which leaves the long path: W-Q1-Q2-Q3-Q4-D, five
 * hops against the planned parts' two. The long path is penalised so the
 * plan takes the primaries, and its private links are hinted by alias.
 */
async function buildChainWorld(
	seedBase: number,
	ceiling: number
): Promise<IChainWorld> {
	const storage = new MemoryStorage();
	const w = createNode(seedBase, storage, {
		recovery: recoveryUnderCeiling(seedBase, storage, ceiling)
	});
	const d = createNode(seedBase + 1);
	const p1 = createNode(seedBase + 2);
	const p2 = createNode(seedBase + 3);
	const chain = [0, 1, 2, 3].map((i) => createNode(seedBase + 4 + i));
	for (const p of [p1, p2]) {
		wire(w, p, { val: false });
		wire(p, d, { val: false });
	}
	const path = [w, ...chain, d];
	for (let i = 0; i < path.length - 1; i++) {
		wire(path[i], path[i + 1], { val: false });
	}
	const wP1 = await openChannelOf(w, p1, 200_000n);
	await openChannelOf(w, p2, 100_000n);
	const links: Array<{ from: LightningNode; to: LightningNode; id: Buffer }> = [
		{ from: p1, to: d, id: await openChannelOf(p1, d, 30_000n) },
		{ from: p2, to: d, id: await openChannelOf(p2, d, 1_000_000n) }
	];
	await openChannelOf(w, chain[0], 230_000n);
	for (let i = 1; i < path.length - 1; i++) {
		links.push({
			from: path[i],
			to: path[i + 1],
			id: await openChannelOf(path[i], path[i + 1], 1_000_000n)
		});
	}
	links.forEach(({ from, to, id }, i) => {
		const scid = hintScidOf(i);
		from.registerChannelScid(id, scid);
		writableState(from.getChannelManager().getChannel(id)!).remoteScidAlias =
			scid;
		writableState(to.getChannelManager().getChannel(id)!).remoteScidAlias =
			scid;
	});
	// D's own hint for P1 prices every hop of the long path: each node runs
	// the same default forwarding policy.
	const priced = decodeInvoice(
		d.createInvoice({ amountMsat: 1_000n, description: 'price' }).bolt11
	).routingHints![0][0];
	const chainHints = [
		chain.map((node, i) => ({
			...priced,
			pubkey: Buffer.from(node.getNodeId(), 'hex'),
			shortChannelId: hintScidOf(2 + i)
		}))
	];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const missionControl = (w as any).missionControl;
	missionControl.recordFailure(hintScidOf(2).toString('hex'));
	missionControl.recordFailure(hintScidOf(5).toString('hex'));
	const room = (
		w as unknown as { recoveryJournal: { mutationRoom(): number } }
	).recoveryJournal.mutationRoom();
	const reader = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(nodePrivkey(seedBase)),
		getPublicKey(nodePrivkey(seedBase)),
		deriveRecoveryRoot(nodePrivkey(seedBase)).recoveryId
	);
	const world: IChainWorld = {
		w,
		d,
		chain,
		nodes: [w, d, p1, p2, ...chain],
		wAdds: 0,
		chainForwards: 0,
		p1Spendable: w
			.getChannelManager()
			.getChannel(wP1)!
			.getSpendableOutboundMsat(),
		chainHints,
		room,
		rowBytes: (paymentHash): number[] => {
			const bytes: number[] = [];
			for (const frame of reader.loadVerifiedFrames()) {
				for (const mutation of frame.mutations) {
					if (
						mutation.type === 'payment_state' &&
						mutation.paymentHash === paymentHash.toString('hex')
					) {
						bytes.push(encodedMutationBytes(mutation));
					}
				}
			}
			return bytes;
		}
	};
	w.on('message:outbound', (_pk: string, type: number) => {
		if (type === MessageType.UPDATE_ADD_HTLC) world.wAdds++;
	});
	chain[0].on('htlc:forward', () => world.chainForwards++);
	return world;
}

const sum = (values: bigint[]): bigint => values.reduce((a, b) => a + b, 0n);

/** Fees the parts pay their primaries, generously. */
const FEE_MARGIN_MSAT = 100_000n;

async function payAndSettle(
	world: IWorld,
	bolt11: string,
	paymentHash: Buffer
): Promise<void> {
	world.w.sendPayment(bolt11);
	await waitFor(
		() => world.w.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
		'the payment to complete on W'
	);
	expect(world.d.getPayment(paymentHash)?.status).to.equal(
		PaymentStatus.COMPLETED
	);
}

describe('MPP across distinct first-hop peers (issue #1922)', function () {
	it('a payment larger than either channel completes with one part over each of two primaries', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7100, [200_000n, 200_000n]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		expect(
			spendable.every((s) => amountMsat > s),
			'neither channel carries it alone'
		).to.equal(true);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'two primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 1]);
		destroyAll(...world.nodes);
	});

	it('without basic_mpp on the invoice the payment is still not split', async function () {
		this.timeout(30_000);
		const seedBase = 7120;
		const world = await buildWorld(seedBase, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;

		// D's own invoice, re-signed with its hints and secret but no basic_mpp.
		const template = decodeInvoice(
			world.d.createInvoice({ amountMsat, description: 'template' }).bolt11
		);
		const features = FeatureFlags.empty();
		features.setCompulsory(Feature.TLV_ONION);
		features.setCompulsory(Feature.PAYMENT_SECRET);
		const dKey = nodePrivkey(seedBase + 1);
		const bolt11 = encodeInvoice({
			network: Network.REGTEST,
			paymentHash: template.paymentHash,
			paymentSecret: template.paymentSecret,
			description: 'no basic_mpp',
			amountMsat,
			payeeNodeKey: getPublicKey(dKey),
			privateKey: dKey,
			featureBits: features,
			routingHints: template.routingHints
		});
		expect(template.routingHints?.length, 'a hint per primary').to.equal(2);

		expect(() => world.w.sendPayment(bolt11)).to.throw('No route found');
		expect(world.wAdds).to.equal(0);
		destroyAll(...world.nodes);
	});

	it('five primaries carry a payment that needs all five, past the four-part default', async function () {
		this.timeout(60_000);
		const world = await buildWorld(7140, [
			100_000n,
			100_000n,
			100_000n,
			100_000n,
			100_000n
		]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		const largestFour = sum(
			[...spendable].sort((a, b) => (a < b ? 1 : -1)).slice(0, 4)
		);
		expect(amountMsat > largestFour, 'four channels do not carry it').to.equal(
			true
		);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'five primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(5);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([
			1, 1, 1, 1, 1
		]);
		destroyAll(...world.nodes);
	});

	it('a 100k and a 20k channel pay their sum in two parts, not four halvings and a refusal', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7160, [100_000n, 20_000n]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		expect(amountMsat > spendable[0]).to.equal(true);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'uneven primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 1]);
		destroyAll(...world.nodes);
	});

	it('a primary channel voided between planning and dispatch fails the payment locally (#1941)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7180, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'primary gone'
		});

		// The first part's update_add_htlc is the moment after planning and
		// before the second part's dispatch: W's channel with the other
		// primary is voided there, as a close or void landing mid-send would.
		let voided: Buffer | undefined;
		world.w.on(
			'message:outbound',
			(_pk: string, type: number, payload: Buffer) => {
				if (type !== MessageType.UPDATE_ADD_HTLC || voided) return;
				const used = payload.subarray(0, 32);
				const other = world.primaries.find((p) => !p.wChannelId.equals(used))!;
				voided = other.wChannelId;
				world.w.getChannelManager().voidChannel(other.wChannelId);
			}
		);
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await settle();

		expect(voided, 'the first part left').to.exist;
		expect(world.wAdds, 'the second part never left').to.equal(1);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureReason).to.match(/first-hop channel is gone/);
		expect(failedEvents, 'payment:failed emitted once').to.equal(1);
		// The dispatched part's secrets stay until D fails it back.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(1);
		// D holds the lone part it was forwarded and credits nothing.
		expect(sum(world.primaries.map((p) => BigInt(p.forwards)))).to.equal(1n);
		expect(world.d.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		destroyAll(...world.nodes);
	});

	it('a part fulfilled before a later part finds its channel gone leaves the payment COMPLETED (#1941)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7200, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'settled mid-dispatch',
			hold: true
		});

		// D settles the first part the moment it is held, as a hold-invoice
		// consumer may. This wire delivers inline, so W holds the preimage
		// before the second part's dispatch step, which then finds W's channel
		// with the other primary voided on the first part's update_add_htlc.
		world.d.on('hold:accepted', () => {
			world.d.settleHeldHtlc(invoice.paymentHash);
		});
		let voided: Buffer | undefined;
		world.w.on(
			'message:outbound',
			(_pk: string, type: number, payload: Buffer) => {
				if (type !== MessageType.UPDATE_ADD_HTLC || voided) return;
				const used = payload.subarray(0, 32);
				const other = world.primaries.find((p) => !p.wChannelId.equals(used))!;
				voided = other.wChannelId;
				world.w.getChannelManager().voidChannel(other.wChannelId);
			}
		);
		const events: string[] = [];
		world.w.on('payment:sent', () => events.push('sent'));
		world.w.on('payment:failed', () => events.push('failed'));

		const payment = world.w.sendPayment(invoice.bolt11);
		await settle();

		expect(voided, 'the first part left').to.exist;
		expect(world.wAdds, 'the second part never left').to.equal(1);
		expect(events, 'the preimage ended the payment').to.deep.equal(['sent']);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.preimage).to.exist;
		expect(payment.failureReason).to.equal(undefined);
		expect(world.w.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(0);
		destroyAll(...world.nodes);
	});

	/**
	 * Three primaries. W's channel with P1 carries most of the amount and the
	 * rest fits P2 or P3; P3 is penalised so the plan takes P2. P2's channel
	 * to D is far too small for its part, which a hint cannot show, so P2
	 * fails the part back with temporary_channel_failure once the siblings
	 * have left.
	 */
	const REMAINDER_MSAT = 50_000_000n;

	it('a part its primary fails is replaced over another primary under the same payment (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7220, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 1_000_000n]
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'replaced part'
		});
		const events: string[] = [];
		world.w.on('payment:sent', () => events.push('sent'));
		world.w.on('payment:failed', () => events.push('failed'));

		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		const payment = world.w.getPayment(invoice.paymentHash)!;
		expect(world.wAdds, 'two planned parts and one replacement').to.equal(3);
		expect(
			world.primaries.map((p) => p.forwards),
			'P2 forwarded nothing, P3 carried the replacement'
		).to.deep.equal([1, 0, 1]);
		expect(payment.retryCount, 'one part replaced').to.equal(1);
		expect(
			payment.failureCode,
			'the part failure stays on the record'
		).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(events, 'one completion event').to.deep.equal(['sent']);
		expect(payment.sentMsat! >= amountMsat).to.equal(true);
		expect(payment.sentMsat! < amountMsat + FEE_MARGIN_MSAT).to.equal(true);
		// Everything D was ever sent is the invoice exactly: the replacement
		// took the failed part's place, it did not join it.
		expect(
			sum(world.primaries.map((p) => p.forwardedMsat)),
			'D received total_msat once'
		).to.equal(amountMsat);
		expect(world.d.getPayment(invoice.paymentHash)!.amountMsat).to.equal(
			amountMsat
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(0);
		destroyAll(...world.nodes);
	});

	it('the failed first hop is excluded from the replacement and the payment fails once every alternative fails (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7240, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 30_000n],
			dExtra: { mppTimeoutMs: 1 }
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'no alternative'
		});
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payment to fail on W'
		);
		await settle();

		expect(
			world.wAdds,
			'P2, then P3 as its replacement, then nothing'
		).to.equal(3);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 0, 0]);
		expect(payment.retryCount).to.equal(1);
		expect(payment.failureReason).to.match(
			/Replacement part not sent: no route/
		);
		expect(failedEvents, 'payment:failed emitted once').to.equal(1);
		// Both failed primaries' hinted channels and W's channels to them are
		// out; P1's channel stays in, it did its part.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const wAny = world.w as any;
		const excluded: Set<string> | undefined = wAny.paymentRetryContexts.get(
			invoice.paymentHash.toString('hex')
		)?.excludedChannels;
		expect(excluded, 'the context went with the payment').to.equal(undefined);
		// D holds P1's part alone and releases it at its MPP timeout; the
		// record is already FAILED, so that failure changes nothing but the
		// code it records.
		await new Promise((r) => setTimeout(r, 5));
		world.d.failTimedOutMppPayments();
		await settle();
		expect(payment.failureCode).to.equal(MPP_TIMEOUT);
		expect(failedEvents).to.equal(1);
		expect(wAny.outboundMppPayments.size).to.equal(0);
		expect(world.d.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		destroyAll(...world.nodes);
	});

	it('the retry bound ends the payment FAILED without a replacement (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7260, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 1_000_000n],
			wExtra: { maxPaymentRetries: 0 }
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'no retries'
		});
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payment to fail on W'
		);
		await settle();

		expect(world.wAdds, 'the two planned parts only').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 0, 0]);
		expect(payment.failureReason).to.match(/0 part retries used/);
		expect(payment.failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(failedEvents).to.equal(1);
		destroyAll(...world.nodes);
	});

	it('a first hop that re-prices its channel to D carries its own replacement at the new price (#1942)', async function () {
		this.timeout(30_000);
		// W's channel with P3 cannot carry the remainder, so only P2 can
		// replace the part P2 fails. P2 fails it with fee_insufficient and a
		// signed channel_update for its channel to D at a higher base fee than
		// the hint carries: a price, not a fault, so neither that channel nor
		// W's channel to P2 is excluded from the replacement.
		const seedBase = 7280;
		const world = await buildWorld(seedBase, [200_000n, 100_000n, 20_000n]);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'repriced first hop'
		});
		const hint = decodeInvoice(invoice.bolt11)
			.routingHints!.flat()
			.find((hop) => hop.shortChannelId.equals(hintScidOf(1)))!;
		const p2Key = nodePrivkey(seedBase + 3);
		const p2Pubkey = getPublicKey(p2Key);
		const dPubkey = getPublicKey(nodePrivkey(seedBase + 1));
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: hintScidOf(1),
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 0,
			channelFlags: Buffer.compare(p2Pubkey, dPubkey) < 0 ? 0 : 1,
			cltvExpiryDelta: hint.cltvExpiryDelta,
			htlcMinimumMsat: 1n,
			feeBaseMsat: hint.feeBaseMsat + 1_000,
			feeProportionalMillionths: hint.feeProportionalMillionths
		};
		const signed = encodeChannelUpdateMessage({
			...update,
			signature: signChannelUpdate(encodeChannelUpdateMessage(update), p2Key)
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p2 = world.primaries[1].node as any;
		const forward = p2.handleForwardHtlc.bind(p2);
		p2.handleForwardHtlc = (
			inChannelId: Buffer,
			inHtlcId: bigint,
			_paymentHash: Buffer,
			processed: { sharedSecret: Buffer },
			incomingAmountMsat: bigint
		): void => {
			p2.handleForwardHtlc = forward;
			// fee_insufficient: [u64 htlc_msat][u16 len][channel_update]
			const data = Buffer.alloc(10 + signed.length);
			data.writeBigUInt64BE(incomingAmountMsat, 0);
			data.writeUInt16BE(signed.length, 8);
			signed.copy(data, 10);
			p2.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(processed.sharedSecret, FEE_INSUFFICIENT, data)
			);
		};
		const actions: string[] = [];
		world.w.on('log', (log: { action: string }) => actions.push(log.action));

		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		const payment = world.w.getPayment(invoice.paymentHash)!;
		expect(actions).to.include('retry_repriced');
		expect(world.wAdds, 'two planned parts and one replacement').to.equal(3);
		expect(
			world.primaries.map((p) => p.forwards),
			'P2 forwarded its own replacement'
		).to.deep.equal([1, 1, 0]);
		expect(payment.retryCount).to.equal(1);
		expect(sum(world.primaries.map((p) => p.forwardedMsat))).to.equal(
			amountMsat
		);
		destroyAll(...world.nodes);
	});

	it('two parts over one primary are both replaced when it re-prices its channel to D (#1942)', async function () {
		this.timeout(30_000);
		// W holds two channels with P1 and the invoice needs both, so both
		// parts cross P1's channel to D. P1 fails each with fee_insufficient
		// and the same signed channel_update, on separate ticks: the second
		// comes back after the first replacement stored the new price. That
		// part was planned at the old price too, so its failure is a re-price
		// as well, not a fault at a known price, and nothing is excluded.
		const seedBase = 7300;
		const world = await buildWorld(seedBase, [200_000n], {
			extraWChannelSats: [200_000n]
		});
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'repriced shared channel'
		});
		const hint = decodeInvoice(invoice.bolt11)
			.routingHints!.flat()
			.find((hop) => hop.shortChannelId.equals(hintScidOf(0)))!;
		const p1Key = nodePrivkey(seedBase + 2);
		const p1Pubkey = getPublicKey(p1Key);
		const dPubkey = getPublicKey(nodePrivkey(seedBase + 1));
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: hintScidOf(0),
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 0,
			channelFlags: Buffer.compare(p1Pubkey, dPubkey) < 0 ? 0 : 1,
			cltvExpiryDelta: hint.cltvExpiryDelta,
			htlcMinimumMsat: 1n,
			feeBaseMsat: hint.feeBaseMsat + 1_000,
			feeProportionalMillionths: hint.feeProportionalMillionths
		};
		const signed = encodeChannelUpdateMessage({
			...update,
			signature: signChannelUpdate(encodeChannelUpdateMessage(update), p1Key)
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p1 = world.primaries[0].node as any;
		const forward = p1.handleForwardHtlc.bind(p1);
		let failed = 0;
		p1.handleForwardHtlc = (
			inChannelId: Buffer,
			inHtlcId: bigint,
			_paymentHash: Buffer,
			processed: { sharedSecret: Buffer },
			incomingAmountMsat: bigint
		): void => {
			if (++failed === 2) p1.handleForwardHtlc = forward;
			const data = Buffer.alloc(10 + signed.length);
			data.writeBigUInt64BE(incomingAmountMsat, 0);
			data.writeUInt16BE(signed.length, 8);
			signed.copy(data, 10);
			p1.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(processed.sharedSecret, FEE_INSUFFICIENT, data)
			);
		};
		const logs: Array<{ action: string; data: Record<string, unknown> }> = [];
		world.w.on('log', (log: (typeof logs)[number]) => logs.push(log));

		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		const payment = world.w.getPayment(invoice.paymentHash)!;
		expect(
			logs.filter((log) => log.action === 'retry_repriced'),
			'each part failure read as a re-price'
		).to.have.length(2);
		// The first part fills its channel, so at the higher fee its
		// replacement no longer fits that channel alone and is re-split over
		// both: the adds are the planned parts plus whatever the replacements
		// were split into.
		const replaced = logs.filter((log) => log.action === 'mpp_part_replaced');
		expect(replaced, 'both parts replaced').to.have.length(2);
		expect(world.wAdds).to.equal(
			replaced.reduce((n, log) => n + (log.data.replacementParts as number), 2)
		);
		expect(
			world.primaries[0].forwardedMsat,
			'P1 forwarded the invoice to D once over'
		).to.equal(amountMsat);
		expect(payment.retryCount).to.equal(2);
		destroyAll(...world.nodes);
	});

	it('a replacement whose record cannot be written is not sent and the payment fails once (#1942)', async function () {
		this.timeout(30_000);
		// The replaced-part world, with W on storage that refuses the one
		// write the replacement needs: the record carrying its debit. The
		// replacement stays home, since a restart after its HTLC landed would
		// find a record short of what the channels show, and the payment ends
		// as one with no route does.
		const storage = new MemoryStorage();
		let refuseNextSave = false;
		const savePayment = storage.savePayment.bind(storage);
		storage.savePayment = (hash: string, record: IPaymentInfo): void => {
			if (refuseNextSave) {
				refuseNextSave = false;
				throw new Error('injected savePayment failure');
			}
			savePayment(hash, record);
		};
		const world = await buildWorld(7320, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 1_000_000n],
			wExtra: { storage }
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'unwritable record'
		});
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);
		const errors: string[] = [];
		world.w.on('node:error', (err: { code: string }) => errors.push(err.code));
		// The failed part's resolution is reported once its mapping is
		// released; the next record write is the replacement's.
		world.w.on('payment:htlc-resolved', () => {
			refuseNextSave = true;
		});

		const payment = world.w.sendPayment(invoice.bolt11);
		const plannedMsat = payment.sentMsat;
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payment to fail on W'
		);
		await settle();

		expect(world.wAdds, 'the two planned parts only').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 0, 0]);
		expect(payment.failureReason).to.match(
			/Replacement part not sent: the payment record could not be persisted/
		);
		expect(payment.retryCount ?? 0, 'no replacement counted').to.equal(0);
		expect(payment.sentMsat, 'the planned parts alone').to.equal(plannedMsat);
		expect(errors).to.include('PERSISTENCE_ERROR');
		expect(failedEvents).to.equal(1);
		const stored = storage.loadPayment(invoice.paymentHash.toString('hex'))!;
		expect(stored.status).to.equal(PaymentStatus.FAILED);
		expect(stored.sentMsat).to.equal(plannedMsat);
		destroyAll(...world.nodes);
	});

	it('a replacement whose longer route would outgrow the labelled payment row is not sent (#1942)', async function () {
		this.timeout(60_000);
		// Guardians this small make the row, not the half-frame rule, what
		// bounds a label: the longest one the planned two-hop parts allow
		// leaves no room in the row for a five-hop route.
		const world = await buildChainWorld(7340, 5_000);
		const amountMsat = world.p1Spendable + REMAINDER_MSAT;
		let payment: IPaymentInfo | undefined;
		for (
			let length = Math.floor(world.room / 2);
			!payment && length > 0;
			length -= 16
		) {
			const invoice = world.d.createInvoice({
				amountMsat,
				description: 'long replacement',
				extraRoutingHints: world.chainHints
			});
			try {
				payment = world.w.sendPaymentWithOptions(invoice.bolt11, {
					metadata: { note: 'x'.repeat(length) }
				});
			} catch (err) {
				if (!(err instanceof InvalidRequestError)) throw err;
			}
		}
		expect(payment, 'a label the planned parts fit').to.exist;
		const sent = payment!;
		await waitFor(
			() => sent.status !== PaymentStatus.PENDING,
			'the payment to resolve on W'
		);
		await settle();

		const rows = world.rowBytes(sent.paymentHash);
		expect(rows).to.not.have.length(0);
		for (const bytes of rows) expect(bytes).to.be.at.most(world.room);
		expect(sent.status).to.equal(PaymentStatus.FAILED);
		expect(sent.failureReason).to.match(
			/replacement part not sent: the payment record would be too large for the recovery guardians/i
		);
		expect(world.wAdds, 'the two planned parts only').to.equal(2);
		expect(world.chainForwards, 'nothing took the long path').to.equal(0);
		expect(sent.retryCount ?? 0, 'no replacement counted').to.equal(0);
		destroyAll(...world.nodes);
	});

	it('a replacement over a longer route takes over a labelled row that still fits (#1942)', async function () {
		this.timeout(60_000);
		const world = await buildChainWorld(7360, 5_000);
		const invoice = world.d.createInvoice({
			amountMsat: world.p1Spendable + REMAINDER_MSAT,
			description: 'long replacement fits',
			extraRoutingHints: world.chainHints
		});
		const payment = world.w.sendPaymentWithOptions(invoice.bolt11, {
			metadata: { note: 'short' }
		});
		await waitFor(
			() => payment.status === PaymentStatus.COMPLETED,
			'the payment to complete on W'
		);

		expect(world.wAdds, 'two planned parts and one replacement').to.equal(3);
		expect(world.chainForwards, 'the replacement took the long path').to.equal(
			1
		);
		expect(payment.retryCount, 'one part replaced').to.equal(1);
		expect(
			payment.route!.hops,
			"the replacement took the failed part's place on the row"
		).to.have.length(5);
		const rows = world.rowBytes(invoice.paymentHash);
		expect(rows).to.not.have.length(0);
		for (const bytes of rows) expect(bytes).to.be.at.most(world.room);
		destroyAll(...world.nodes);
	});
});
