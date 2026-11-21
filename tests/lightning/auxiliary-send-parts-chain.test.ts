/**
 * Issue #2098, step 9: the ends on the chain of an asset payment sent in
 * parts. Alice, the wallet, sends each part to Bob over one of her two
 * asset channels with him, and one part's channel goes to the chain. A part
 * that Alice's timeout takes back there, or that is on no output of the
 * commitment that confirmed, fails alone: the listing marks it, the
 * record's figures leave it out, and the record stays PENDING with no
 * payment:failed while another part is out. Its end is told once, whatever
 * its siblings do, and the record turns FAILED once when the last part
 * fails. A preimage learned on the chain completes the record once. Once
 * the record is COMPLETED, a part that ends otherwise on the chain leaves
 * the figures as they were when it completed, and is logged
 * asset_part_ended_after_payment once.
 *
 * The cases run on the chain world of auxiliary-forward-world.ts, asset in
 * and bitcoin out, through the scene of auxiliary-send-scene.ts: Bob values
 * each part and forwards it to Carol, who holds the set under a hold
 * invoice or collects it. In one case Bob is the payee. What Alice and Bob
 * send each other is lost while a channel goes to the chain, so the other
 * part stays out in its own channel until their link comes back.
 *
 * Written first: on the build before step 9, which refuses an asset HTLC
 * whose total is above its value (ASSET_PAYMENT_UNSUPPORTED), each case of
 * new behaviour fails at its first part, and the cases of a payment of one
 * HTLC pass. The contract is "An asset payment sent in parts" in
 * docs/EXTENSIONS.md.
 */

import { expect } from 'chai';
import type {
	IAuxiliarySweepContext,
	IChannelAuxiliaryProvider
} from '../../src/lightning/channel/auxiliary';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	PaymentStatus,
	type IPaymentHtlcResolvedEvent
} from '../../src/lightning/node/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { rounds } from './helpers/auxiliary-forward-scene';
import {
	FORWARD_CARRIER_MSAT,
	forwardChainWorld,
	heldPartsInvoice,
	partsInvoice,
	sendAssetPart,
	type IAssetPartSent
} from './helpers/auxiliary-forward-world';
import {
	RECEIVE_IN_PARTS,
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	withAssetPartsSent,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	errorsOf,
	trackedOutputs
} from './helpers/auxiliary-on-chain';
import { collected } from './helpers/auxiliary-parts-checks';
import {
	openSendScene,
	timeOutSets,
	type ISendScene,
	type ISendSceneOptions,
	type Log
} from './helpers/auxiliary-send-scene';

const hex = (value: Buffer): string => value.toString('hex');
const CARRIER = FORWARD_CARRIER_MSAT;
/** The units of Alice's in each of her asset channels with Bob when it opens. */
const ALICE_UNITS = 9000n;
/**
 * Blocks above the tip at which the last hop of a part that is to outlive
 * another part's end on the chain expires: past that end, which comes
 * IRREVOCABLE_DEPTH blocks after a timeout at the other part's expiry.
 */
const FAR = 300;
/** The log of a part that ends otherwise after the payment completed. */
const ENDED_AFTER = 'asset_part_ended_after_payment';

/** A part as the listing gives it, without the live view of its HTLC. */
interface IListed {
	channelId: Buffer;
	htlcId: bigint;
	amountMsat: bigint;
	routeAmountMsat?: bigint;
	wireAmountMsat?: bigint;
	failed: boolean;
}

/** What the listing of an asset payment says of each part, in the order sent. */
function recorded(node: LightningNode, paymentHash: Buffer): IListed[] {
	return (
		node.getAuxiliaryPaymentHtlcs(paymentHash) as unknown as Array<
			IListed & { failed?: boolean }
		>
	).map((entry) => ({
		channelId: entry.channelId,
		htlcId: entry.htlcId,
		amountMsat: entry.amountMsat,
		routeAmountMsat: entry.routeAmountMsat,
		wireAmountMsat: entry.wireAmountMsat,
		failed: entry.failed === true
	}));
}

/** What the listing says of a part sent in the new path. */
const entryOf = (part: IAssetPartSent, failed = false): IListed => ({
	channelId: part.channelId,
	htlcId: part.htlcId,
	amountMsat: part.valueMsat,
	routeAmountMsat: part.routeAmountMsat,
	wireAmountMsat: part.wireAmountMsat,
	failed
});

const figures = (
	node: LightningNode,
	paymentHash: Buffer
):
	| {
			status: PaymentStatus;
			amountMsat: bigint;
			auxiliaryValueMsat?: bigint;
	  }
	| undefined => {
	const payment = node.getPayment(paymentHash);
	return payment
		? {
				status: payment.status,
				amountMsat: payment.amountMsat,
				auxiliaryValueMsat: payment.auxiliaryValueMsat
		  }
		: undefined;
};

/** The send went through: it returned a record and threw nothing. */
function sentOk(part: IAssetPartSent): void {
	expect(part.error, `the part was not sent: ${String(part.error)}`).to.equal(
		undefined
	);
	expect(part.payment, 'the send returned the record').to.not.equal(undefined);
}

const countOf = (list: string[], paymentHash: Buffer): number =>
	list.filter((entry) => entry === hex(paymentHash)).length;

const endOf = (outcome: string, part: IAssetPartSent): string =>
	`${outcome}:${hex(part.channelId)}:${part.htlcId}`;

const unitsOf = (host: IAssetHost, channelId: Buffer): bigint =>
	host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

const plain = (value: unknown): unknown =>
	JSON.parse(
		JSON.stringify(value, (_key, item: unknown) =>
			typeof item === 'bigint' ? `${item}n` : item
		)
	);

/** A log's field as text: a buffer as hex. */
const textOf = (value: unknown): string =>
	Buffer.isBuffer(value) ? hex(value) : String(value);

/** The scene, with Alice's payment:htlc-resolved kept in order. */
interface IChainScene extends ISendScene {
	htlcEnds: IPaymentHtlcResolvedEvent[];
}

/**
 * Bob's provider, refusing to sign his claim by a preimage of any HTLC of
 * the channel the arm names: the asset store signs no such claim, so the
 * HTLC is left on the chain for Alice's timeout.
 */
function refusingClaims(arm: {
	channelId?: Buffer;
}): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (key !== 'prepareSweep' || typeof value !== 'function') return value;
				return (context: IAuxiliarySweepContext): unknown => {
					const channelId = context.state.channelId;
					if (
						arm.channelId !== undefined &&
						channelId !== null &&
						channelId.equals(arm.channelId) &&
						context.inputs.some(
							(input) =>
								input.kind === 'htlc_success' ||
								input.kind === 'htlc_second_level_success'
						)
					) {
						throw new Error('the asset store signs no claim of this channel');
					}
					return (value as (given: IAuxiliarySweepContext) => unknown).call(
						target,
						context
					);
				};
			}
		});
}

/** Bob's host as a payee: each asset HTLC is worth 1000 msat a unit. */
const unitsAt1000: IAuxiliaryChannelConfig['valueIncomingHtlc'] = (context) =>
	context.auxiliaryAmount === undefined
		? undefined
		: context.auxiliaryAmount * 1000n;

describe('the ends on the chain of an asset payment sent in parts (issue #2098, step 9)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	withAssetPartsSent();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/**
	 * The send scene with a second asset channel of Alice's with Bob, and
	 * more fee coins for every host: each commitment's child and each
	 * spend of an HTLC output takes one.
	 */
	const open = async (
		tag: string,
		options: ISendSceneOptions = {},
		coins = 2
	): Promise<IChainScene> => {
		const s = (await openSendScene(world, tag, {
			...options,
			world: { secondIn: 'asset', ...options.world }
		})) as IChainScene;
		s.htlcEnds = [];
		s.w.hosts.alice.node.on(
			'payment:htlc-resolved',
			(event: IPaymentHtlcResolvedEvent) => {
				s.htlcEnds.push(event);
			}
		);
		for (const name of ['alice', 'bob', 'carol'] as const) {
			for (let i = 0; i < coins; i++) s.w.wallets[name]!.fund(100_000);
		}
		await world.mine(s.w, 1);
		return s;
	};

	/** Blocks, one at a time, until `reached`, or throw with what is missing. */
	const until = async (
		s: IChainScene,
		what: string,
		reached: () => boolean,
		most = 30
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(s.w, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what} at ${s.w.chain.height}; alice: ${errorsOf(
					s.w.hosts.alice
				).join(' | ')}; bob: ${errorsOf(s.w.hosts.bob).join(' | ')}`
			);
		}
	};

	/** The states Alice's payment:htlc-resolved gave a part, in order. */
	const partEnds = (s: IChainScene, part: IAssetPartSent): string[] =>
		s.htlcEnds
			.filter(
				(event) =>
					event.channelId.equals(part.channelId) && event.htlcId === part.htlcId
			)
			.map((event) => event.state);

	/** The ends Alice's host was told of for a hash, as `outcome:channel:id`, sorted. */
	const endsFor = (s: IChainScene, paymentHash: Buffer): string[] =>
		s.resolved
			.filter((end) => end.paymentHash.equals(paymentHash))
			.map((end) => `${end.outcome}:${hex(end.channelId)}:${end.htlcId}`)
			.sort();

	/** Alice's structured logs of a kind. */
	const logsFor = (s: IChainScene, action: string): Log[] =>
		s.aliceLogs.filter((log) => log.action === action);

	/** The log names the part (and the payment), where it gives them. */
	const namesPart = (
		log: Log,
		part: IAssetPartSent,
		paymentHash: Buffer
	): void => {
		const data = log.data;
		if (data.channelId !== undefined) {
			expect(textOf(data.channelId), 'the part the log names').to.equal(
				hex(part.channelId)
			);
		}
		if (data.htlcId !== undefined) {
			expect(textOf(data.htlcId), 'the part the log names').to.equal(
				String(part.htlcId)
			);
		}
		if (data.paymentHash !== undefined) {
			expect(textOf(data.paymentHash)).to.equal(hex(paymentHash));
		}
	};

	/** What Alice's record and listing say, and what she told and emitted, for a hash. */
	const counted = (s: IChainScene, paymentHash: Buffer): unknown =>
		plain({
			listing: recorded(s.w.hosts.alice.node, paymentHash),
			figures: figures(s.w.hosts.alice.node, paymentHash),
			htlcEnds: s.htlcEnds.filter((event) =>
				event.paymentHash.equals(paymentHash)
			).length,
			told: endsFor(s, paymentHash),
			sent: countOf(s.sent, paymentHash),
			failed: countOf(s.failed, paymentHash),
			endedAfter: logsFor(s, ENDED_AFTER).length
		});

	/** How Alice's node sees a part's HTLC (getOutgoingHtlcs). */
	const stateOf = (
		s: IChainScene,
		paymentHash: Buffer,
		part: IAssetPartSent
	): string | undefined =>
		s.w.hosts.alice.node
			.getOutgoingHtlcs(paymentHash)
			.htlcs.find(
				(view) =>
					view.channelId.equals(part.channelId) && view.htlcId === part.htlcId
			)?.state;

	/** The HTLCs of a hash Carol holds under a hold invoice. */
	const heldAtCarol = (s: IChainScene, paymentHash: Buffer): number =>
		(
			(
				s.w.hosts.carol.node as unknown as {
					heldHtlcs: Map<string, unknown[]>;
				}
			).heldHtlcs.get(hex(paymentHash)) ?? []
		).length;
	const carolHolds = (
		s: IChainScene,
		paymentHash: Buffer,
		parts: number
	): Promise<void> =>
		rounds(
			`Carol holds ${parts} parts`,
			() => heldAtCarol(s, paymentHash) === parts,
			60
		);

	/** The expiry of a part's HTLC on Alice's channel. */
	const expiryOf = (s: IChainScene, part: IAssetPartSent): number =>
		s.w.hosts.alice.node
			.getChannelManager()
			.getChannel(part.channelId)!
			.getFullState()
			.htlcs.get(`offered-${part.htlcId}`)!.cltvExpiry;

	/** Alice's first-level output of a part's HTLC, on the commitment that confirmed. */
	const outputOf = (
		host: IAssetHost,
		part: IAssetPartSent
	): ITrackedOutput | undefined =>
		trackedOutputs(host, part.channelId).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC &&
				!output.isSecondLevelHtlc &&
				output.htlcId === part.htlcId
		);
	const spentAt = (output: ITrackedOutput | undefined): number | undefined =>
		output &&
		(output.status === OutputStatus.SPEND_CONFIRMED ||
			output.status === OutputStatus.IRREVOCABLY_RESOLVED)
			? output.confirmationHeight
			: undefined;

	/** A host takes a channel to the chain by itself. */
	const closes = (
		s: IChainScene,
		who: 'alice' | 'bob',
		channelId: Buffer
	): void => {
		const closed = s.w.hosts[who].node.forceCloseChannel(
			channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
	};

	/**
	 * The link between Alice and Bob comes back: each is told the other
	 * went, and they reestablish, so what was lost is sent again.
	 */
	const bringBack = async (s: IChainScene): Promise<void> => {
		world.cut(s.w, 'in');
		await world.reconnect(s.w, 'in');
		await turns(50);
	};

	/**
	 * Blocks pass to just before Carol cancels the set she holds, at
	 * HELD_HTLC_EXPIRY_MARGIN before its first part's last hop expires
	 * (60 blocks above the tip it was sent at), then one at a time until
	 * she has.
	 */
	const throughCarolsCancel = async (
		s: IChainScene,
		paymentHash: Buffer,
		sentAt: number
	): Promise<void> => {
		await world.passTo(s.w, sentAt + 40);
		await until(
			s,
			'Carol cancels the set she holds',
			() => heldAtCarol(s, paymentHash) === 0,
			10
		);
		await turns(50);
	};

	/**
	 * Blocks pass to just before a part's expiry, then one at a time until
	 * Alice's timeout of its output is in a block; the height of that block.
	 */
	const timedOut = async (
		s: IChainScene,
		part: IAssetPartSent,
		expiry: number
	): Promise<number> => {
		await world.passTo(s.w, expiry - 8);
		await until(
			s,
			"Alice's timeout of the part in a block",
			() => spentAt(outputOf(s.w.hosts.alice, part)) !== undefined
		);
		const at = spentAt(outputOf(s.w.hosts.alice, part))!;
		expect(at, 'taken back after its expiry').to.be.at.least(expiry);
		return at;
	};

	/**
	 * Blocks pass to just before the spend of a part's output, or the
	 * commitment it is absent from, is there for good, then one at a time
	 * until Alice tells the part's end.
	 */
	const toldEnd = async (
		s: IChainScene,
		part: IAssetPartSent,
		from: number
	): Promise<void> => {
		await world.passTo(s.w, from + IRREVOCABLE_DEPTH - 3);
		await until(
			s,
			"the part's end, told",
			() => partEnds(s, part).length > 0,
			8
		);
		await turns(50);
	};

	/** Bob's ordinary invoice, for Alice's parts to pay him as the payee. */
	const bobsInvoice = (
		s: IChainScene,
		tag: string,
		invoiceMsat: bigint
	): { paymentHash: Buffer; paymentSecret: Buffer; totalMsat: bigint } => {
		const invoice = s.w.hosts.bob.node.createInvoice({
			amountMsat: invoiceMsat,
			description: `parts to Bob ${tag}`
		});
		return {
			paymentHash: invoice.paymentHash,
			paymentSecret: invoice.paymentSecret,
			totalMsat: invoiceMsat
		};
	};

	/** Alice sends Bob, the payee, one part of his invoice: one hop, its own units. */
	const partToBob = (
		s: IChainScene,
		invoice: { paymentHash: Buffer; paymentSecret: Buffer; totalMsat: bigint },
		options: { valueMsat: bigint; units: bigint; channelId: Buffer }
	): IAssetPartSent =>
		sendAssetPart(s.w, invoice, {
			valueMsat: options.valueMsat,
			units: options.units,
			routeAmountMsat: options.valueMsat,
			channelId: options.channelId,
			hops: [
				{
					pubkey: Buffer.from(s.w.hosts.bob.node.getNodeId(), 'hex'),
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat: options.valueMsat,
					outgoingCltvValue: 40
				}
			]
		});

	describe('a part timed out on the chain', () => {
		for (const closer of ['alice', 'bob'] as const) {
			const who = closer === 'alice' ? 'Alice' : 'Bob';
			it(`${who} takes one part's channel to the chain, and the part Alice's timeout takes back there after its expiry fails alone: the listing marks it, the figures leave it out, its end is told once, and the record stays PENDING with no payment:failed while the other part is out; when the other part fails too, the record is FAILED once`, async () => {
				const tag = `send-parts-chain-timeout-${closer}`;
				const s = await open(tag);
				const alice = s.w.hosts.alice;
				const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
				const h = invoice.paymentHash;
				const sentAt = s.w.chain.height;
				const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
				sentOk(first);
				// The other part, over the other channel, outlives the first
				// part's end on the chain.
				const second = sendAssetPart(s.w, invoice, {
					valueMsat: 2_000_000n,
					channelId: s.w.inChannel2,
					outgoingDelta: FAR
				});
				sentOk(second);
				await carolHolds(s, h, 2);
				const expiry = expiryOf(s, first);
				expect(expiryOf(s, second)).to.be.greaterThan(
					expiry + IRREVOCABLE_DEPTH + 20
				);
				// What Alice and Bob send each other is lost from here on, and
				// each still takes the other to be there.
				world.silence(s.w, 'in');
				closes(s, closer, s.w.inChannel);
				await world.mine(s.w, 1);
				// Carol cancels the set; Bob's fail of the second part does not
				// reach Alice, and the first part's channel is on the chain.
				await throughCarolsCancel(s, h, sentAt);
				expect(figures(alice.node, h)).to.deep.equal({
					status: PaymentStatus.PENDING,
					amountMsat: 2n * CARRIER,
					auxiliaryValueMsat: 5_000_000n
				});

				const timedOutAt = await timedOut(s, first, expiry);
				expect(alice.node.getPayment(h)?.status).to.equal(
					PaymentStatus.PENDING
				);
				await toldEnd(s, first, timedOutAt);
				expect(partEnds(s, first), 'its end, told once').to.deep.equal([
					'onchain-resolved'
				]);
				expect(partEnds(s, second)).to.deep.equal([]);
				expect(recorded(alice.node, h)).to.deep.equal([
					entryOf(first, true),
					entryOf(second)
				]);
				expect(figures(alice.node, h)).to.deep.equal({
					status: PaymentStatus.PENDING,
					amountMsat: CARRIER,
					auxiliaryValueMsat: 2_000_000n
				});
				expect(countOf(s.failed, h), 'no payment:failed').to.equal(0);
				expect(countOf(s.sent, h)).to.equal(0);
				expect(stateOf(s, h, second), 'the other part is out').to.equal(
					'offered'
				);
				expect(unitsOf(alice, s.w.inChannel2!), 'its units with it').to.equal(
					ALICE_UNITS - second.units
				);
				expect(endsFor(s, h)).to.deep.equal([endOf('failed', first)]);
				expect(logsFor(s, ENDED_AFTER)).to.deep.equal([]);
				const before = counted(s, h);
				await world.mine(s.w, 2);
				expect(counted(s, h), 'two more blocks change nothing').to.deep.equal(
					before
				);

				// The link comes back, and Bob's fail of the second part with it.
				await bringBack(s);
				await rounds(
					'the payment fails at Alice',
					() => alice.node.getPayment(h)?.status === PaymentStatus.FAILED,
					60
				);
				await turns(100);
				expect(figures(alice.node, h)).to.deep.equal({
					status: PaymentStatus.FAILED,
					amountMsat: 2n * CARRIER,
					auxiliaryValueMsat: 5_000_000n
				});
				expect(countOf(s.failed, h), 'payment:failed once').to.equal(1);
				expect(countOf(s.sent, h)).to.equal(0);
				expect(recorded(alice.node, h)).to.deep.equal([
					entryOf(first, true),
					entryOf(second, true)
				]);
				expect(partEnds(s, first)).to.deep.equal(['onchain-resolved']);
				expect(
					partEnds(s, second).filter((state) => state.startsWith('onchain'))
				).to.deep.equal([]);
				expect(endsFor(s, h)).to.deep.equal(
					[endOf('failed', first), endOf('failed', second)].sort()
				);
				expect(unitsOf(alice, s.w.inChannel2!)).to.equal(ALICE_UNITS);
				expect(logsFor(s, ENDED_AFTER)).to.deep.equal([]);
			});
		}
	});

	describe('a part on no output of the commitment that confirmed', () => {
		it('a part sent while Bob heard nothing of it, his commitment without it confirmed, fails alone once that commitment is there for good: its end is told once, the listing marks it, and the record stays PENDING with no payment:failed while the other part is out; when the other part fails too, the record is FAILED once', async () => {
			const tag = 'send-parts-chain-absent';
			const s = await open(tag);
			const { alice, bob, carol } = s.w.hosts;
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			// The other part, in the set Carol collects, outlives the first
			// part's end on the chain.
			const other = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2,
				outgoingDelta: FAR
			});
			sentOk(other);
			await rounds(
				'Carol collects the other part',
				() => collected(carol, h) === 1,
				60
			);
			world.silence(s.w, 'in');
			const absent = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(absent);
			await turns(50);
			expect(
				bob.node.getChannelManager().getChannel(s.w.inChannel)!.getFullState()
					.htlcs.size,
				'Bob heard nothing of the part'
			).to.equal(0);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(other),
				entryOf(absent)
			]);
			closes(s, 'bob', s.w.inChannel);
			await world.mine(s.w, 1);
			const closedAt = s.w.chain.height;

			await toldEnd(s, absent, closedAt);
			expect(partEnds(s, absent), 'its end, told once').to.deep.equal([
				'onchain-resolved'
			]);
			expect(partEnds(s, other)).to.deep.equal([]);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(other),
				entryOf(absent, true)
			]);
			expect(figures(alice.node, h)).to.deep.equal({
				status: PaymentStatus.PENDING,
				amountMsat: CARRIER,
				auxiliaryValueMsat: 2_000_000n
			});
			expect(countOf(s.failed, h), 'no payment:failed').to.equal(0);
			expect(countOf(s.sent, h)).to.equal(0);
			expect(stateOf(s, h, other), 'the other part is out').to.equal('offered');
			expect(unitsOf(alice, s.w.inChannel2!), 'its units with it').to.equal(
				ALICE_UNITS - other.units
			);
			expect(endsFor(s, h)).to.deep.equal([endOf('failed', absent)]);
			expect(logsFor(s, ENDED_AFTER)).to.deep.equal([]);
			const before = counted(s, h);
			await world.mine(s.w, 3);
			expect(counted(s, h), 'three more blocks change nothing').to.deep.equal(
				before
			);

			// The set's time runs out at Carol, and the link comes back.
			timeOutSets(carol);
			await turns(50);
			await bringBack(s);
			await rounds(
				'the payment fails at Alice',
				() => alice.node.getPayment(h)?.status === PaymentStatus.FAILED,
				60
			);
			await turns(100);
			expect(figures(alice.node, h)).to.deep.equal({
				status: PaymentStatus.FAILED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.failed, h), 'payment:failed once').to.equal(1);
			expect(countOf(s.sent, h)).to.equal(0);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(other, true),
				entryOf(absent, true)
			]);
			expect(partEnds(s, absent)).to.deep.equal(['onchain-resolved']);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('failed', absent), endOf('failed', other)].sort()
			);
			expect(unitsOf(alice, s.w.inChannel2!)).to.equal(ALICE_UNITS);
		});

		it('a part sent while Bob heard nothing of it, of a record COMPLETED through its other part, leaves the record COMPLETED with the figures it completed with: its end is told once, the listing marks it, and asset_part_ended_after_payment comes once, for it', async () => {
			const tag = 'send-parts-chain-absent-paid';
			// Bob is the payee here, valuing each part by the units it carries.
			const s = await open(tag, {
				bob: { ...RECEIVE_IN_PARTS, valueIncomingHtlc: unitsAt1000 }
			});
			const { alice, bob } = s.w.hosts;
			const invoice = bobsInvoice(s, tag, 5_000_000n);
			const h = invoice.paymentHash;
			world.silence(s.w, 'in');
			const absent = partToBob(s, invoice, {
				valueMsat: 2_000_000n,
				units: 2000n,
				channelId: s.w.inChannel
			});
			sentOk(absent);
			await turns(50);
			closes(s, 'bob', s.w.inChannel);
			await world.mine(s.w, 1);
			const closedAt = s.w.chain.height;
			await bringBack(s);
			// The other part carries the units of the whole invoice: Bob's
			// host takes it as paying the set by itself.
			const paying = partToBob(s, invoice, {
				valueMsat: 3_000_000n,
				units: 5000n,
				channelId: s.w.inChannel2!
			});
			sentOk(paying);
			await rounds(
				'Alice is paid',
				() => alice.node.getPayment(h)?.status === PaymentStatus.COMPLETED,
				60
			);
			await turns(100);
			expect(bob.node.getPayment(h)?.status).to.equal(PaymentStatus.COMPLETED);
			const paid = figures(alice.node, h);
			expect(paid, 'the figures it completed with').to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h), 'payment:sent once').to.equal(1);
			expect(stateOf(s, h, absent)).to.equal('onchain-pending');

			await toldEnd(s, absent, closedAt);
			expect(partEnds(s, absent), 'its end, told once').to.deep.equal([
				'onchain-resolved'
			]);
			expect(figures(alice.node, h), 'the figures stay').to.deep.equal(paid);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(absent, true),
				entryOf(paying)
			]);
			const logs = logsFor(s, ENDED_AFTER);
			expect(logs.length, `${ENDED_AFTER} once`).to.equal(1);
			namesPart(logs[0], absent, h);
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h), 'no payment:failed').to.equal(0);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('failed', absent), endOf('fulfilled', paying)].sort()
			);
			expect(unitsOf(alice, s.w.inChannel2!)).to.equal(
				ALICE_UNITS - paying.units
			);
			const before = counted(s, h);
			await world.mine(s.w, 3);
			expect(counted(s, h), 'three more blocks change nothing').to.deep.equal(
				before
			);
		});
	});

	describe('a preimage learned on the chain', () => {
		it("Bob's claim of one part on the chain by its preimage completes the record once, with the figures of both parts out, and the other part fulfilled afterwards in its channel changes nothing", async () => {
			const tag = 'send-parts-chain-preimage';
			const s = await open(tag);
			const { alice, carol } = s.w.hosts;
			const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			await carolHolds(s, h, 2);
			// Bob's fulfil of the second part, in its channel, does not reach
			// Alice: the preimage comes to her on the chain.
			world.silence(s.w, 'in');
			closes(s, 'alice', s.w.inChannel);
			await world.mine(s.w, 2);
			expect(carol.node.settleHeldHtlc(h, invoice.preimage)).to.equal(true);
			await turns(50);
			await until(
				s,
				'Alice learns the preimage on the chain',
				() => alice.node.getPayment(h)?.status === PaymentStatus.COMPLETED
			);
			await turns(50);
			const claimedAt = spentAt(outputOf(alice, first));
			expect(
				claimedAt,
				"Bob's claim of the first part, in a block"
			).to.not.equal(undefined);
			const paid = figures(alice.node, h);
			expect(paid).to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h), 'payment:sent once').to.equal(1);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);
			expect(stateOf(s, h, second), 'the other part is still out').to.equal(
				'offered'
			);

			await bringBack(s);
			await rounds(
				'the other part is fulfilled',
				() => endsFor(s, h).includes(endOf('fulfilled', second)),
				60
			);
			await turns(50);
			expect(figures(alice.node, h)).to.deep.equal(paid);
			expect(countOf(s.sent, h)).to.equal(1);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second)
			]);

			await toldEnd(s, first, claimedAt!);
			expect(partEnds(s, first), 'its end, told once').to.deep.equal([
				'onchain-resolved'
			]);
			expect(figures(alice.node, h)).to.deep.equal(paid);
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('fulfilled', first), endOf('fulfilled', second)].sort()
			);
			expect(logsFor(s, ENDED_AFTER)).to.deep.equal([]);
			expect(unitsOf(alice, s.w.inChannel2!)).to.equal(
				ALICE_UNITS - second.units
			);
		});
	});

	describe('after the payment completed', () => {
		it("with one part claimed by Bob on the chain by its preimage, which completes the record, the other part that Alice's timeout takes back there leaves it COMPLETED with the figures it completed with: the listing marks that part, its end is told once, and asset_part_ended_after_payment comes once, for that part alone", async () => {
			const tag = 'send-parts-chain-after-paid';
			const refuse: { channelId?: Buffer } = {};
			const s = await open(
				tag,
				{ world: { wrapProvider: { bob: refusingClaims(refuse) } } },
				3
			);
			// Bob's asset store signs no claim of the second channel's HTLCs.
			refuse.channelId = s.w.inChannel2;
			const { alice, carol } = s.w.hosts;
			const invoice = heldPartsInvoice(s.w, tag, 5_000_000n);
			const h = invoice.paymentHash;
			const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(first);
			const second = sendAssetPart(s.w, invoice, {
				valueMsat: 2_000_000n,
				channelId: s.w.inChannel2
			});
			sentOk(second);
			await carolHolds(s, h, 2);
			const expiry = expiryOf(s, second);
			world.silence(s.w, 'in');
			closes(s, 'alice', s.w.inChannel);
			closes(s, 'alice', s.w.inChannel2!);
			await world.mine(s.w, 2);
			expect(carol.node.settleHeldHtlc(h, invoice.preimage)).to.equal(true);
			await turns(50);
			await until(
				s,
				"Alice learns the preimage from Bob's claim",
				() => alice.node.getPayment(h)?.status === PaymentStatus.COMPLETED
			);
			await turns(50);
			const paid = figures(alice.node, h);
			expect(paid, 'the figures it completed with').to.deep.equal({
				status: PaymentStatus.COMPLETED,
				amountMsat: 2n * CARRIER,
				auxiliaryValueMsat: 5_000_000n
			});
			expect(countOf(s.sent, h), 'payment:sent once').to.equal(1);
			expect(
				spentAt(outputOf(alice, second)),
				'Bob claims no second part'
			).to.equal(undefined);

			const timedOutAt = await timedOut(s, second, expiry);
			await toldEnd(s, second, timedOutAt);
			expect(partEnds(s, second), 'its end, told once').to.deep.equal([
				'onchain-resolved'
			]);
			expect(partEnds(s, first)).to.deep.equal(['onchain-resolved']);
			expect(alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(figures(alice.node, h), 'the figures stay').to.deep.equal(paid);
			expect(recorded(alice.node, h)).to.deep.equal([
				entryOf(first),
				entryOf(second, true)
			]);
			const logs = logsFor(s, ENDED_AFTER);
			expect(logs.length, `${ENDED_AFTER} once`).to.equal(1);
			namesPart(logs[0], second, h);
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h), 'no payment:failed').to.equal(0);
			expect(endsFor(s, h)).to.deep.equal(
				[endOf('fulfilled', first), endOf('failed', second)].sort()
			);
			const before = counted(s, h);
			await world.mine(s.w, 2);
			expect(counted(s, h), 'two more blocks change nothing').to.deep.equal(
				before
			);
		});
	});

	describe('a payment of one HTLC on the chain, as before', () => {
		for (const optIn of [true, false]) {
			it(`${
				optIn ? 'with' : 'without'
			} the opt-in: the HTLC Alice's timeout takes back on the chain fails the record once, with payment:failed once and its end told once`, async () => {
				const tag = `send-parts-chain-one-timeout-${optIn ? 'in' : 'out'}`;
				const s = await open(tag, { optIn });
				const alice = s.w.hosts.alice;
				const invoice = heldPartsInvoice(s.w, tag, 3_000_000n);
				const h = invoice.paymentHash;
				const sentAt = s.w.chain.height;
				const only = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
				sentOk(only);
				await carolHolds(s, h, 1);
				const expiry = expiryOf(s, only);
				world.silence(s.w, 'in');
				closes(s, 'alice', s.w.inChannel);
				await world.mine(s.w, 1);
				await throughCarolsCancel(s, h, sentAt);
				const timedOutAt = await timedOut(s, only, expiry);
				expect(alice.node.getPayment(h)?.status).to.equal(
					PaymentStatus.PENDING
				);
				await toldEnd(s, only, timedOutAt);
				expect(alice.node.getPayment(h)?.status).to.equal(PaymentStatus.FAILED);
				expect(countOf(s.failed, h), 'payment:failed once').to.equal(1);
				expect(countOf(s.sent, h)).to.equal(0);
				expect(partEnds(s, only)).to.deep.equal(['onchain-resolved']);
				expect(endsFor(s, h)).to.deep.equal([endOf('failed', only)]);
				expect(logsFor(s, ENDED_AFTER)).to.deep.equal([]);
				const before = counted(s, h);
				await world.mine(s.w, 2);
				expect(counted(s, h)).to.deep.equal(before);
			});
		}

		it('with the opt-in: the HTLC Bob claims on the chain by its preimage completes the record once, and its end is told once', async () => {
			const tag = 'send-parts-chain-one-preimage';
			const s = await open(tag);
			const { alice, carol } = s.w.hosts;
			const invoice = heldPartsInvoice(s.w, tag, 3_000_000n);
			const h = invoice.paymentHash;
			const only = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
			sentOk(only);
			await carolHolds(s, h, 1);
			world.silence(s.w, 'in');
			closes(s, 'alice', s.w.inChannel);
			await world.mine(s.w, 2);
			expect(carol.node.settleHeldHtlc(h, invoice.preimage)).to.equal(true);
			await turns(50);
			await until(
				s,
				'Alice learns the preimage on the chain',
				() => alice.node.getPayment(h)?.status === PaymentStatus.COMPLETED
			);
			await turns(50);
			expect(countOf(s.sent, h), 'payment:sent once').to.equal(1);
			const claimedAt = spentAt(outputOf(alice, only));
			expect(claimedAt).to.not.equal(undefined);
			await toldEnd(s, only, claimedAt!);
			expect(partEnds(s, only)).to.deep.equal(['onchain-resolved']);
			expect(alice.node.getPayment(h)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(countOf(s.sent, h)).to.equal(1);
			expect(countOf(s.failed, h)).to.equal(0);
			expect(endsFor(s, h)).to.deep.equal([endOf('fulfilled', only)]);
		});
	});
});
