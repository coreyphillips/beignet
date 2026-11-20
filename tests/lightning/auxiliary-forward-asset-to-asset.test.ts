/**
 * Issue #2098, step 4: asset in, asset out.
 *
 * With the switch for asset forwards on, a node in the middle forwards an
 * HTLC that came in on an asset channel carrying units over another asset
 * channel of its own: the one the onion names, or the one its host names for
 * a short channel id made from one of its quotes. The host is asked once,
 * after the node wrote that it asks and outside any storage transaction, for
 * what the incoming HTLC is worth and for the records and carrier of the
 * outgoing one. The forward goes on when that value covers the amount to
 * forward and the node's fee; neither carrier is taken for what its HTLC is
 * worth. The incoming leg's ends are those of step 3 (its decision written
 * with its channel's row, its link kept until a removal is taken), and the
 * outgoing leg's those of step 2.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type {
	IAuxiliaryForwardLegResolution,
	IAuxiliaryForwardRequest,
	IAuxiliaryForwardTerms
} from '../../src/lightning/channel/auxiliary-forward';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { auxiliaryForwards } from '../../src/lightning/channel/auxiliary-switch';
import {
	hasScidAliasChannelType,
	HtlcDirection
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	INCORRECT_CLTV_EXPIRY,
	TEMPORARY_CHANNEL_FAILURE,
	UNKNOWN_NEXT_PEER
} from '../../src/lightning/onion/types';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	failingProvider,
	fixRandomness,
	openAssetChannel,
	reconnectHosts,
	restoreRandomness,
	turns,
	withAssetForwards,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** The scid of a route's first hop; Alice's asset payment goes over her asset channel. */
const FIRST_HOP_SCID = Buffer.from('0001f40000010000', 'hex');

/** A short channel id no channel of Bob's has: one of his host's quotes. */
const QUOTE_SCID = hash(
	'a quote of the middle node for its asset channel'
).subarray(0, 8);

/** The units Alice sends Bob, and what Bob's host values each at. */
const INCOMING_UNITS = 5010n;
const MSAT_PER_UNIT = 1000n;
/** The units Bob's host makes the outgoing HTLC carry, and what the onion asks Bob to forward. */
const OUTGOING_UNITS = 5000n;
const FORWARD_MSAT = 5_000_000n;
/** The bitcoin each asset HTLC carries on the wire. */
const CARRIER_MSAT = 354_000n;

interface IContext {
	/** Alice's asset channel with Bob, on which the HTLC comes in. */
	inChannel: Buffer;
	/** Bob's asset channel with Carol, over which it goes on. */
	outChannel: Buffer;
	alice: string;
	carol: string;
}

type Answer = (
	request: IAuxiliaryForwardRequest,
	context: IContext
) => IAuxiliaryForwardTerms | undefined;

/**
 * The terms of a host that values each incoming unit at MSAT_PER_UNIT and
 * pays OUTGOING_UNITS on the outgoing channel, naming that channel when the
 * request names none.
 */
const terms = (
	request: IAuxiliaryForwardRequest,
	context: IContext,
	extra: Record<string, unknown> = {}
): IAuxiliaryForwardTerms =>
	({
		...(request.outgoing === undefined
			? {
					outgoingChannel: {
						channelId: context.outChannel,
						peerPubkey: context.carol
					}
			  }
			: {}),
		incomingValueMsat: request.incoming.auxiliaryAmount! * MSAT_PER_UNIT,
		outgoingHtlc: {
			customRecords: amountRecord(OUTGOING_UNITS),
			wireAmountMsat: CARRIER_MSAT
		},
		...extra
	}) as IAuxiliaryForwardTerms;

/**
 * What the onion names as Bob's next hop: the outgoing asset channel by Bob's
 * own alias or by the one Carol gave it, a quote's short channel id, the
 * asset channel the HTLC came in on, a short channel id the JIT receive
 * minted, or the outgoing channel's real id when its type has
 * option_scid_alias.
 */
type Next = 'alias' | 'peer-alias' | 'quote' | 'incoming' | 'jit' | 'real';

interface IOptions {
	/** Bob's host's prepareForward. Absent: the host supplies no forward hook. */
	answer?: Answer;
	/** The next hop the onion names; Bob's own alias of the out channel when left out. */
	next?: Next;
	/** The expiry the onion asks of Bob's outgoing HTLC. */
	forwardCltv?: number;
	/**
	 * Bob's row of the incoming HTLC says he asks before he dispatches it, as
	 * after a stop between that write and keeping the answer.
	 */
	markedBefore?: boolean;
	/** Bob's bound on HTLCs in flight across his channels refuses the HTLC. */
	inFlightCap?: boolean;
	/** A delegated settlement slot of Bob's holds the payment hash. */
	fforSlot?: boolean;
	/** The switch for asset forwards is off. */
	switchOff?: boolean;
	/** Carol announced that she accepts no HTLC on the outgoing channel. */
	peerTakesNone?: boolean;
}

interface IResult {
	context: IContext;
	paymentHash: Buffer;
	asked: IAuxiliaryForwardRequest[];
	/** Whether Bob's storage was inside a transaction at each ask. */
	inTransaction: boolean[];
	/** Whether Bob's stored row of the incoming channel said, at each ask, that he asks. */
	markedBeforeAsk: boolean[];
	told: IAuxiliaryForwardLegResolution[];
	/** Bob's other hooks, in order. */
	hooks: string[];
	/** How often Bob's host was asked to value an HTLC that ends at Bob. */
	valuedHere: number;
	alice: PaymentStatus | undefined;
	failure: [number | undefined, number | undefined];
	carol: PaymentStatus | undefined;
	/** The asset HTLC as Carol's host saw it. */
	carolSaw: { wireAmountMsat?: bigint; units?: bigint; records?: string };
	/** HTLCs Bob offered on his channel with Carol. */
	offered: bigint;
	/** Bob's units, and Alice's, on the incoming channel. */
	inUnits: [bigint, bigint];
	/** Bob's units, and Carol's, on the outgoing channel. */
	outUnits: [bigint, bigint];
	/** Bob's bitcoin on each channel, before and after. */
	inBalance: [bigint, bigint];
	outBalance: [bigint, bigint];
	/** The decision Bob's stored row of the incoming channel holds for HTLC 0. */
	decision: string | undefined;
	/** Every batch of mutations Bob committed, by their types. */
	commits: string[][];
	links: number;
	forwards: number;
}

describe('an asset HTLC forwarded out over another asset channel (issue #2098, step 4)', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetForwards();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		restoreRandomness();
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	/**
	 * Alice pays Carol's invoice of 5,000,000 msat through Bob with 5,010
	 * units over her asset channel with Bob (9,000 units hers, 1,000 his).
	 * Bob holds an asset channel with Carol (9,000 units his, 1,000 hers) and
	 * runs on SQLite. Carol's host values each unit at 1,000 msat.
	 */
	async function run(tag: string, options: IOptions): Promise<IResult> {
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const inTransaction: boolean[] = [];
		const markedBeforeAsk: boolean[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const hooks: string[] = [];
		const carolSaw: IResult['carolSaw'] = {};
		let valuedHere = 0;
		const context = {} as IContext;
		const made: { bob?: IAssetHost } = {};
		const forwardHooks: Partial<IAuxiliaryChannelConfig> = options.answer
			? {
					prepareForward: (request): IAuxiliaryForwardTerms | undefined => {
						asked.push(request);
						inTransaction.push(made.bob!.storage!.inTransaction());
						const stored = made.bob!.storage!.loadChannel(
							request.incoming.channelId.toString('hex')
						);
						markedBeforeAsk.push(
							stored?.state.htlcs.get(`received-${request.incoming.htlcId}`)
								?.forwardAsked === true
						);
						return options.answer!(request, context);
					},
					onForwardLegResolved: (resolution): void => {
						told.push(resolution);
					}
			  }
			: {};
		const alice = assetHost(tag, 1, {});
		const bob = assetHost(
			tag,
			2,
			{
				onHtlcResolved: (resolved) => {
					hooks.push(
						`onHtlcResolved:${resolved.direction}:${resolved.outcome}`
					);
				},
				valueIncomingHtlc: (incoming) => {
					valuedHere++;
					return incoming.auxiliaryAmount === undefined
						? undefined
						: incoming.auxiliaryAmount * MSAT_PER_UNIT;
				},
				...forwardHooks
			},
			{ sqlite: true }
		);
		made.bob = bob;
		const carol = assetHost(tag, 3, {
			valueIncomingHtlc: (incoming) => {
				carolSaw.wireAmountMsat = incoming.wireAmountMsat;
				carolSaw.units = incoming.auxiliaryAmount;
				carolSaw.records = [...incoming.customRecords]
					.map(([type, value]) => `${type}:${value.toString('hex')}`)
					.join(',');
				return incoming.auxiliaryAmount === undefined
					? undefined
					: incoming.auxiliaryAmount * MSAT_PER_UNIT;
			}
		});
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		context.inChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.outChannel = await openAssetChannel(bob, carol, {
			tag: `${tag} out`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.alice = alice.node.getNodeId();
		context.carol = carol.node.getNodeId();
		await settle();

		const manager = bob.node.getChannelManager();
		const outState = manager.getChannel(context.outChannel)!.getFullState();
		const inState = manager.getChannel(context.inChannel)!.getFullState();
		const outBalanceBefore = outState.localBalanceMsat;
		const inBalanceBefore = inState.localBalanceMsat;
		if (options.next === 'real') {
			// The channel's type with option_scid_alias, and the real short
			// channel id a confirmed funding gives it: BOLT 2 forbids
			// forwarding over such a channel by that id, so the node never put
			// it in its map.
			const state = outState as {
				channelType: Buffer | null;
				shortChannelId?: Buffer;
			};
			const type = FeatureFlags.fromBuffer(
				state.channelType ?? Buffer.alloc(0)
			);
			type.setCompulsory(Feature.SCID_ALIAS);
			state.channelType = type.toBuffer();
			expect(hasScidAliasChannelType(state.channelType)).to.equal(true);
			state.shortChannelId ??= Buffer.from('0dbba00000070000', 'hex');
		}
		if (options.next === 'jit') {
			// A JIT receive that minted the short channel id the onion names.
			const minted = QUOTE_SCID.toString('hex');
			(
				bob.node as unknown as { jitReceiveManager: unknown }
			).jitReceiveManager = new Proxy(
				{},
				{
					get: (_target, property): unknown =>
						property === 'mintedScid'
							? (scidHex: string): boolean => scidHex === minted
							: (): undefined => undefined
				}
			);
		}
		if (options.peerTakesNone) {
			(
				outState as { remoteConfig: { maxAcceptedHtlcs: number } }
			).remoteConfig.maxAcceptedHtlcs = 0;
		}
		const next = ((): Buffer => {
			switch (options.next ?? 'alias') {
				case 'alias':
					expect(
						outState.scidAlias,
						'the out channel has an alias'
					).to.not.equal(undefined);
					return outState.scidAlias!;
				case 'peer-alias':
					expect(
						outState.remoteScidAlias,
						'the out channel has an alias of the peer'
					).to.not.equal(undefined);
					return outState.remoteScidAlias!;
				case 'quote':
				case 'jit':
					return QUOTE_SCID;
				case 'incoming':
					return bob.node.getAuxiliaryChannelInfo(context.inChannel)!
						.shortChannelId!;
				case 'real':
					return outState.shortChannelId!;
			}
		})();

		const invoice = carol.node.createInvoice({
			amountMsat: FORWARD_MSAT,
			description: tag
		});
		if (options.markedBefore) {
			const node = bob.node as unknown as {
				handleIncomingHtlc: (
					channelId: Buffer,
					htlcId: bigint,
					...rest: unknown[]
				) => unknown;
			};
			const dispatch = node.handleIncomingHtlc.bind(bob.node);
			node.handleIncomingHtlc = (channelId, htlcId, ...rest): unknown => {
				expect(manager.recordForwardAsk(channelId, htlcId)).to.equal(true);
				return dispatch(channelId, htlcId, ...rest);
			};
		}
		if (options.inFlightCap) {
			(
				bob.node as unknown as { maxTotalInFlightHtlcs: number }
			).maxTotalInFlightHtlcs = -1;
		}
		if (options.fforSlot) {
			const slots = manager as unknown as {
				fforFindDelegatedSlot: (paymentHash: Buffer) => unknown;
			};
			slots.fforFindDelegatedSlot = (paymentHash): unknown =>
				paymentHash.equals(invoice.paymentHash)
					? {
							channelId: context.outChannel,
							record: {},
							entry: { k: 0 }
					  }
					: undefined;
		}
		// Every batch Bob commits, by the types of its mutations.
		const commits: string[][] = [];
		const recovery = (
			bob.node as unknown as {
				recovery: {
					commit: (input: { mutations: Array<{ type: string }> }) => unknown;
				};
			}
		).recovery;
		const commit = recovery.commit.bind(recovery);
		recovery.commit = (input): unknown => {
			commits.push(input.mutations.map((mutation) => mutation.type));
			return commit(input);
		};
		if (options.switchOff) auxiliaryForwards.enabled = false;
		try {
			alice.node.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
							shortChannelId: FIRST_HOP_SCID,
							amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
							outgoingCltvValue: 240
						},
						{
							pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
							shortChannelId: next,
							amountToForwardMsat: FORWARD_MSAT,
							outgoingCltvValue: options.forwardCltv ?? 40
						}
					]
				},
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				undefined,
				undefined,
				undefined,
				undefined,
				{
					assetPayment: {
						channelId: context.inChannel,
						wireAmountMsat: CARRIER_MSAT,
						customRecords: amountRecord(INCOMING_UNITS)
					}
				}
			);
			await settle();
			await settle();
		} finally {
			auxiliaryForwards.enabled = true;
		}

		const outAfter = manager.getChannel(context.outChannel)!.getFullState();
		const inAfter = manager.getChannel(context.inChannel)!.getFullState();
		return {
			context,
			paymentHash: invoice.paymentHash,
			asked,
			inTransaction,
			markedBeforeAsk,
			told,
			hooks,
			valuedHere,
			alice: alice.node.getPayment(invoice.paymentHash)?.status,
			failure: [
				alice.node.getPayment(invoice.paymentHash)?.failureCode,
				alice.node.getPayment(invoice.paymentHash)?.failureSourceIndex
			],
			carol: carol.node.getPayment(invoice.paymentHash)?.status,
			carolSaw,
			offered: outAfter.localHtlcCounter,
			inUnits: [
				inAfter.auxiliaryState!.localBalance,
				inAfter.auxiliaryState!.remoteBalance
			],
			outUnits: [
				outAfter.auxiliaryState!.localBalance,
				outAfter.auxiliaryState!.remoteBalance
			],
			inBalance: [inBalanceBefore, inAfter.localBalanceMsat],
			outBalance: [outBalanceBefore, outAfter.localBalanceMsat],
			decision: (
				bob
					.storage!.loadChannel(context.inChannel.toString('hex'))
					?.state.auxiliaryState?.htlcDecisions?.get('0') as
					| { outcome: string }
					| undefined
			)?.outcome,
			commits,
			links: bob.storage!.loadAllForwardedHtlcs().length,
			forwards: bob.storage!.listForwardingEvents().length
		};
	}

	/** The checks of a forward that went through. */
	function forwarded(result: IResult): void {
		expect(result.alice).to.equal(PaymentStatus.COMPLETED);
		expect(result.carol).to.equal(PaymentStatus.COMPLETED);
		// The host's records and carrier reached Carol.
		expect(result.carolSaw).to.deep.equal({
			wireAmountMsat: CARRIER_MSAT,
			units: OUTGOING_UNITS,
			records: `65536:${amountRecord(OUTGOING_UNITS)
				.get(65536n)!
				.toString('hex')}`
		});
		expect(result.offered).to.equal(1n);
		// Bob holds the units Alice sent and gave Carol the ones his host
		// made, and each carrier moved with its HTLC.
		expect(result.inUnits).to.deep.equal([
			1000n + INCOMING_UNITS,
			9000n - INCOMING_UNITS
		]);
		expect(result.outUnits).to.deep.equal([
			9000n - OUTGOING_UNITS,
			1000n + OUTGOING_UNITS
		]);
		expect(result.inBalance[1] - result.inBalance[0]).to.equal(CARRIER_MSAT);
		expect(result.outBalance[0] - result.outBalance[1]).to.equal(CARRIER_MSAT);
		// Asked once, after the node wrote that it asks, outside any storage
		// transaction; told nothing, since nothing was refused. The hook of
		// an HTLC that ends at the node is not asked about a forward.
		expect(result.asked).to.have.length(1);
		expect(result.inTransaction).to.deep.equal([false]);
		expect(result.markedBeforeAsk).to.deep.equal([true]);
		expect(result.told).to.deep.equal([]);
		expect(result.valuedHere).to.equal(0);
		// The host hears of each asset HTLC: the one received on the incoming
		// channel and the one offered on the outgoing channel.
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.RECEIVED}:fulfilled`
		);
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.OFFERED}:fulfilled`
		);
		// The link went with the settle. A forward with an asset leg is not
		// recorded in the forwarding history yet.
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
	}

	/** The checks of a forward refused at Bob before anything was offered. */
	function refused(result: IResult, failureCode: number): void {
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.failure).to.deep.equal([failureCode, 0]);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(0n);
		expect(result.inUnits).to.deep.equal([1000n, 9000n]);
		expect(result.outUnits).to.deep.equal([9000n, 1000n]);
		expect(result.valuedHere).to.equal(0);
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
	}

	/** The one never-offered a host is told when it answered with terms. */
	function toldNeverOffered(result: IResult, outChannel?: Buffer): void {
		expect(result.told).to.have.length(1);
		const [told] = result.told;
		expect(told).to.deep.include({
			incomingHtlcId: 0n,
			leg: 'outgoing',
			outcome: 'never-offered',
			onChain: false
		});
		expect(told.paymentHash.equals(result.paymentHash)).to.equal(true);
		expect(told.incomingChannelId.equals(result.context.inChannel)).to.equal(
			true
		);
		if (outChannel) expect(told.channelId?.equals(outChannel)).to.equal(true);
	}

	it('over the asset channel the onion names by its alias: asked once with the request as the contract gives it, and Carol is paid the units the host made', async () => {
		const result = await run('aux-fwd-a2a-alias', {
			answer: (request, context) => terms(request, context)
		});
		forwarded(result);
		const [request] = result.asked;
		expect(request.paymentHash.equals(result.paymentHash)).to.equal(true);
		expect(
			request.incoming.channelId.equals(result.context.inChannel)
		).to.equal(true);
		expect(request.incoming).to.deep.include({
			peerPubkey: result.context.alice,
			htlcId: 0n,
			wireAmountMsat: CARRIER_MSAT,
			auxiliaryAmount: INCOMING_UNITS,
			auxiliaryChannel: true
		});
		expect([...request.incoming.customRecords]).to.deep.equal([
			...amountRecord(INCOMING_UNITS)
		]);
		expect(request.amountToForwardMsat).to.equal(FORWARD_MSAT);
		expect(request.outgoingCltvExpiry).to.equal(40);
		const outgoing = request.outgoing!;
		expect(outgoing.channelId.equals(result.context.outChannel)).to.equal(true);
		expect(outgoing).to.deep.include({
			peerPubkey: result.context.carol,
			auxiliaryChannel: true
		});
	});

	it('over the asset channel the onion names by the alias its peer gave it', async () => {
		const result = await run('aux-fwd-a2a-peer-alias', {
			next: 'peer-alias',
			answer: (request, context) => terms(request, context)
		});
		forwarded(result);
	});

	it("to a short channel id the host claims for a quote: the request names no outgoing channel, and the terms name Bob's asset channel with Carol", async () => {
		const result = await run('aux-fwd-a2a-quote', {
			next: 'quote',
			answer: (request, context) => terms(request, context)
		});
		forwarded(result);
		const [request] = result.asked;
		expect(request.shortChannelId.equals(QUOTE_SCID)).to.equal(true);
		expect(request.outgoing).to.equal(undefined);
		expect(request.incoming.auxiliaryChannel).to.equal(true);
	});

	it("a failure downstream fails the payer back with the downstream's own failure, the link goes with it, and the host is not told the leg was never offered", async () => {
		const result = await run('aux-fwd-a2a-downstream', {
			// Carol's host values the units under her invoice.
			answer: (request, context) =>
				terms(request, context, {
					outgoingHtlc: {
						customRecords: amountRecord(4000n),
						wireAmountMsat: CARRIER_MSAT
					}
				})
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		// The failure is Carol's, relayed as she made it.
		expect(result.failure[1]).to.equal(1);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(1n);
		expect(result.inUnits).to.deep.equal([1000n, 9000n]);
		expect(result.outUnits).to.deep.equal([9000n, 1000n]);
		expect(result.asked).to.have.length(1);
		expect(result.links).to.equal(0);
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.RECEIVED}:failed`
		);
		expect(result.told).to.deep.equal([]);
	});

	interface INotAsked {
		name: string;
		options: IOptions;
		failure: number;
	}

	const NOT_ASKED: INotAsked[] = [
		{
			name: 'the asset channel the HTLC came in on',
			options: {
				next: 'incoming',
				answer: (request, context) => terms(request, context)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'a short channel id the JIT receive minted',
			options: {
				next: 'jit',
				answer: (request, context) => terms(request, context)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'the real short channel id of an asset channel whose type has option_scid_alias',
			options: {
				next: 'real',
				answer: (request, context) => terms(request, context)
			},
			failure: UNKNOWN_NEXT_PEER
		},
		{
			name: 'a host without prepareForward',
			options: {},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'the switch for asset forwards off',
			options: {
				switchOff: true,
				answer: (request, context) => terms(request, context)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'an outgoing channel whose peer takes no more HTLCs',
			options: {
				peerTakesNone: true,
				answer: (request, context) => terms(request, context)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: "an incoming expiry short of the outgoing channel's CLTV delta",
			options: {
				// 20 blocks over the outgoing expiry, under the policy's delta.
				forwardCltv: 220,
				answer: (request, context) => terms(request, context)
			},
			failure: INCORRECT_CLTV_EXPIRY
		},
		{
			name: 'a payment hash a delegated settlement slot of the node holds',
			options: {
				fforSlot: true,
				answer: (request, context) => terms(request, context)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		}
	];

	for (const notAsked of NOT_ASKED) {
		it(`asks nothing and refuses as before for ${notAsked.name}`, async () => {
			const result = await run(
				`aux-fwd-a2a-not-asked-${NOT_ASKED.indexOf(notAsked)}`,
				notAsked.options
			);
			refused(result, notAsked.failure);
			expect(result.asked).to.deep.equal([]);
			expect(result.told).to.deep.equal([]);
		});
	}

	interface IRefusal {
		name: string;
		next?: Next;
		answer: Answer;
		failure?: number;
		/** Whether the host answered with terms, and is told never-offered. */
		told: boolean;
		/** The channel the host is told of, when told. */
		channel?: 'out' | 'in' | 'none';
	}

	const REFUSALS: IRefusal[] = [
		{
			name: 'a throw',
			answer: (): IAuxiliaryForwardTerms => {
				throw new Error('no such quote');
			},
			told: false
		},
		{
			name: 'a promise',
			answer: (request, context) =>
				Promise.resolve(
					terms(request, context)
				) as unknown as IAuxiliaryForwardTerms,
			told: false
		},
		{
			name: 'undefined on the asset channel the onion names',
			answer: () => undefined,
			told: false
		},
		{
			name: 'undefined on a quote',
			next: 'quote',
			answer: () => undefined,
			told: false
		},
		{
			name: 'a field the forward does not call for',
			answer: (request, context) =>
				terms(request, context, {
					outgoingChannel: {
						channelId: context.outChannel,
						peerPubkey: context.carol
					}
				}),
			told: true,
			channel: 'out'
		},
		{
			name: 'no value',
			answer: (request, context) =>
				terms(request, context, { incomingValueMsat: undefined }),
			told: true,
			channel: 'out'
		},
		{
			name: 'no outgoing HTLC',
			answer: (request, context) =>
				terms(request, context, { outgoingHtlc: undefined }),
			told: true,
			channel: 'out'
		},
		{
			name: 'a value that is not a bigint',
			answer: (request, context) =>
				terms(request, context, { incomingValueMsat: 5_010_000 }),
			told: true,
			channel: 'out'
		},
		{
			name: 'terms that throw while they are read',
			answer: (request, context): IAuxiliaryForwardTerms => {
				const answer = terms(request, context) as unknown as Record<
					string,
					unknown
				>;
				Object.defineProperty(answer, 'incomingValueMsat', {
					enumerable: true,
					get: () => {
						throw new Error('the quote book is closed');
					}
				});
				return answer as unknown as IAuxiliaryForwardTerms;
			},
			told: true,
			channel: 'out'
		},
		{
			name: "a value that does not cover the amount to forward and the node's fee",
			answer: (request, context) =>
				terms(request, context, { incomingValueMsat: FORWARD_MSAT }),
			told: true,
			channel: 'out'
		},
		{
			name: "a value that does not cover the amount to forward and the node's fee, on a quote",
			next: 'quote',
			answer: (request, context) =>
				terms(request, context, { incomingValueMsat: FORWARD_MSAT }),
			told: true,
			channel: 'out'
		},
		{
			name: 'a quote that leads back over the asset channel the HTLC came in on',
			next: 'quote',
			answer: (request, context) =>
				terms(request, context, {
					outgoingChannel: {
						channelId: context.inChannel,
						peerPubkey: context.alice
					}
				}),
			told: true,
			channel: 'in'
		},
		{
			name: 'a quote whose outgoing channel names the wrong peer',
			next: 'quote',
			answer: (request, context) =>
				terms(request, context, {
					outgoingChannel: {
						channelId: context.outChannel,
						peerPubkey: context.alice
					}
				}),
			told: true,
			channel: 'out'
		},
		{
			name: "a quote whose incoming expiry is short of the outgoing channel's CLTV delta",
			next: 'quote',
			answer: (request, context) => terms(request, context),
			failure: INCORRECT_CLTV_EXPIRY,
			told: true,
			channel: 'out'
		},
		{
			name: 'an outgoing HTLC of more units than Bob holds on the channel',
			answer: (request, context) =>
				terms(request, context, {
					outgoingHtlc: {
						customRecords: amountRecord(9001n),
						wireAmountMsat: CARRIER_MSAT
					}
				}),
			told: true,
			channel: 'out'
		},
		{
			name: 'a carrier under the dust limit',
			answer: (request, context) =>
				terms(request, context, {
					outgoingHtlc: {
						customRecords: amountRecord(OUTGOING_UNITS),
						wireAmountMsat: 300_000n
					}
				}),
			told: true,
			channel: 'out'
		}
	];

	for (const refusal of REFUSALS) {
		it(`refuses ${refusal.name} before anything is offered, never quoting a carrier, and tells the host only when it answered with terms`, async () => {
			const result = await run(
				`aux-fwd-a2a-refused-${REFUSALS.indexOf(refusal)}`,
				{
					next: refusal.next,
					answer: refusal.answer,
					...(refusal.failure === INCORRECT_CLTV_EXPIRY
						? { forwardCltv: 220 }
						: {})
				}
			);
			refused(result, refusal.failure ?? TEMPORARY_CHANNEL_FAILURE);
			expect(result.asked).to.have.length(1);
			// No row ever held a link for the HTLC it did not offer.
			expect(
				result.commits.some((types) => types.includes('forwarded_htlc'))
			).to.equal(false);
			if (refusal.told) {
				toldNeverOffered(
					result,
					refusal.channel === 'in'
						? result.context.inChannel
						: refusal.channel === 'out'
						? result.context.outChannel
						: undefined
				);
				expect(result.told[0].customRecords.size).to.equal(0);
			} else {
				expect(result.told).to.deep.equal([]);
			}
		});
	}

	it('asks again about an HTLC it had marked as asked before a stop, named or by a quote, while the forward passes the checks made before the ask', async () => {
		forwarded(
			await run('aux-fwd-a2a-marked-named', {
				markedBefore: true,
				answer: (request, context) => terms(request, context)
			})
		);
		forwarded(
			await run('aux-fwd-a2a-marked-quote', {
				markedBefore: true,
				next: 'quote',
				answer: (request, context) => terms(request, context)
			})
		);
	});

	it('tells the host the outgoing leg was never offered when a check before the ask refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-a2a-marked-refused', {
			markedBefore: true,
			peerTakesNone: true,
			answer: (request, context) => terms(request, context)
		});
		refused(result, TEMPORARY_CHANNEL_FAILURE);
		expect(result.asked).to.deep.equal([]);
		toldNeverOffered(result, result.context.outChannel);
	});

	it('tells the host the outgoing leg was never offered when the bound on HTLCs in flight refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-a2a-marked-cap', {
			markedBefore: true,
			inFlightCap: true,
			answer: (request, context) => terms(request, context)
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.offered).to.equal(0n);
		expect(result.asked).to.deep.equal([]);
		toldNeverOffered(result);
		expect(result.told[0].channelId).to.equal(undefined);
	});

	/**
	 * Alice, Bob and Carol as in run(), with Bob on a SQLite file so he can
	 * stop and start again, and Carol holding the payment on a hold invoice
	 * so the forward stays in flight until the test ends it.
	 */
	async function scene(
		tag: string,
		bobExtra: (arm: {
			down: boolean;
			channel?: Buffer;
		}) => Partial<IAuxiliaryChannelConfig>,
		route: 'alias' | 'quote' = 'alias'
	): Promise<{
		alice: IAssetHost;
		bob: IAssetHost;
		carol: IAssetHost;
		bobFile: string;
		directory: string;
		context: IContext;
		asked: IAuxiliaryForwardRequest[];
		told: IAuxiliaryForwardLegResolution[];
		hooks: () => Partial<IAuxiliaryChannelConfig>;
		arm: { down: boolean; channel?: Buffer };
		preimage: Buffer;
		paymentHash: Buffer;
	}> {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), `${tag}-`));
		const bobFile = path.join(directory, 'bob.sqlite');
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const arm: { down: boolean; channel?: Buffer } = { down: false };
		const context = {} as IContext;
		const hooks = (): Partial<IAuxiliaryChannelConfig> => ({
			prepareForward: (request): IAuxiliaryForwardTerms => {
				asked.push(request);
				return terms(request, context);
			},
			onForwardLegResolved: (resolution): void => {
				told.push(resolution);
			},
			...bobExtra(arm)
		});
		const alice = assetHost(tag, 1, {});
		const bob = assetHost(tag, 2, hooks(), { sqlitePath: bobFile });
		const carol = assetHost(tag, 3, {
			valueIncomingHtlc: (incoming) =>
				incoming.auxiliaryAmount === undefined
					? undefined
					: incoming.auxiliaryAmount * MSAT_PER_UNIT
		});
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		context.inChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.outChannel = await openAssetChannel(bob, carol, {
			tag: `${tag} out`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.alice = alice.node.getNodeId();
		context.carol = carol.node.getNodeId();
		arm.channel = context.inChannel;
		await settle();
		const outAlias = bob.node
			.getChannelManager()
			.getChannel(context.outChannel)!
			.getFullState().scidAlias!;

		const preimage = createHash('sha256').update(`${tag} preimage`).digest();
		const paymentHash = createHash('sha256').update(preimage).digest();
		const invoice = carol.node.createInvoice({
			amountMsat: FORWARD_MSAT,
			description: tag,
			hold: true,
			paymentHash
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: FIRST_HOP_SCID,
						amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
						shortChannelId: route === 'quote' ? QUOTE_SCID : outAlias,
						amountToForwardMsat: FORWARD_MSAT,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId: context.inChannel,
					wireAmountMsat: CARRIER_MSAT,
					customRecords: amountRecord(INCOMING_UNITS)
				}
			}
		);
		await settle();
		await settle();
		expect(asked).to.have.length(1);
		expect(bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		return {
			alice,
			bob,
			carol,
			bobFile,
			directory,
			context,
			asked,
			told,
			hooks,
			arm,
			preimage,
			paymentHash
		};
	}

	/**
	 * Bob's provider cannot build a commitment of the incoming channel while
	 * `arm.down`; the outgoing channel goes on as it is.
	 */
	const refuser = (arm: {
		down: boolean;
		channel?: Buffer;
	}): Partial<IAuxiliaryChannelConfig> => ({
		provider: failingProvider(
			(method, args) =>
				method === 'buildCommitment' &&
				arm.down &&
				arm.channel !== undefined &&
				(
					args[0] as { state: { channelId?: Buffer | null } }
				).state.channelId?.equals(arm.channel) === true
		)
	});

	/** The refusals of its asset provider a host reported. */
	const refusals = (host: IAssetHost, operation: string): string[] =>
		host.errors.filter((error) =>
			error.includes(`The asset provider refused ${operation}`)
		);

	/** The decision Bob's stored row of the incoming channel holds for HTLC 0. */
	const storedDecision = (
		host: IAssetHost,
		channelId: Buffer
	): { outcome: string; preimage?: Buffer } | undefined =>
		host
			.storage!.loadChannel(channelId.toString('hex'))
			?.state.auxiliaryState?.htlcDecisions?.get('0') as
			| { outcome: string; preimage?: Buffer }
			| undefined;

	/** Bob, stopped and started again from his SQLite file. */
	function restart(
		s: Awaited<ReturnType<typeof scene>>,
		tag: string
	): IAssetHost {
		s.bob.node.destroy();
		s.bob.storage!.close();
		const restarted = assetHost(tag, 2, s.hooks(), { sqlitePath: s.bobFile });
		hosts.push(restarted);
		connectHosts(s.alice, restarted);
		connectHosts(restarted, s.carol);
		return restarted;
	}

	/** Bob's links in memory: the forwards he would settle or fail upstream. */
	const linksInMemory = (host: IAssetHost): number =>
		(host.node as unknown as { forwardedHtlcs: Map<string, unknown> })
			.forwardedHtlcs.size;

	for (const route of ['alias', 'quote'] as const) {
		it(`asks once (${route}): a reestablish and a restart with the forward in flight on both asset channels ask nothing again, and the payment still settles`, async () => {
			const tag = `aux-fwd-a2a-restart-${route}`;
			const s = await scene(tag, () => ({}), route);
			await reconnectHosts(s.alice, s.bob);
			await reconnectHosts(s.bob, s.carol);
			expect(s.asked).to.have.length(1);

			const restarted = restart(s, tag);
			await reconnectHosts(s.alice, restarted);
			await reconnectHosts(restarted, s.carol);
			await settle();
			expect(s.asked).to.have.length(1);
			expect(restarted.storage!.loadAllForwardedHtlcs()).to.have.length(1);

			expect(s.carol.node.settleHeldHtlc(s.paymentHash, s.preimage)).to.equal(
				true
			);
			await settle();
			await settle();
			expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(restarted.storage!.loadAllForwardedHtlcs()).to.have.length(0);
			const manager = restarted.node.getChannelManager();
			const inState = manager.getChannel(s.context.inChannel)!.getFullState();
			const outState = manager.getChannel(s.context.outChannel)!.getFullState();
			expect([
				inState.auxiliaryState!.localBalance,
				inState.auxiliaryState!.remoteBalance
			]).to.deep.equal([1000n + INCOMING_UNITS, 9000n - INCOMING_UNITS]);
			expect([
				outState.auxiliaryState!.localBalance,
				outState.auxiliaryState!.remoteBalance
			]).to.deep.equal([9000n - OUTGOING_UNITS, 1000n + OUTGOING_UNITS]);
			expect(outState.localHtlcCounter).to.equal(1n);
			expect(s.told).to.deep.equal([]);
			fs.rmSync(s.directory, { recursive: true, force: true });
		});
	}

	it('writes its decision to settle with the incoming asset channel as soon as the preimage comes back, keeps the link while the payer is away, and settles once the payer is back', async () => {
		const tag = 'aux-fwd-a2a-away';
		const s = await scene(tag, () => ({}));
		s.bob.node.getChannelManager().handlePeerDisconnected(s.context.alice);
		s.alice.node
			.getChannelManager()
			.handlePeerDisconnected(s.bob.node.getNodeId());
		await turns(20);

		expect(s.carol.node.settleHeldHtlc(s.paymentHash, s.preimage)).to.equal(
			true
		);
		await settle();
		await settle();
		const decision = storedDecision(s.bob, s.context.inChannel);
		expect(decision?.outcome).to.equal('settle');
		expect(decision?.preimage?.equals(s.preimage)).to.equal(true);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		await reconnectHosts(s.alice, s.bob);
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		expect(s.asked).to.have.length(1);
		expect(s.told).to.deep.equal([]);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('keeps the link while its provider refuses the settlement upstream, with and without a restart, and Carol is offered one HTLC', async () => {
		for (const stop of [false, true]) {
			const tag = `aux-fwd-a2a-provider-refuses-${stop}`;
			const s = await scene(tag, refuser);
			s.arm.down = true;
			expect(s.carol.node.settleHeldHtlc(s.paymentHash, s.preimage)).to.equal(
				true
			);
			await settle();
			await settle();
			// Carol is paid; Alice is not settled yet, and Bob keeps what lets
			// him settle her: the link, and the decision with the channel.
			expect(refusals(s.bob, 'the settlement of an HTLC')).to.have.length(1);
			expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
			expect(storedDecision(s.bob, s.context.inChannel)?.outcome).to.equal(
				'settle'
			);

			s.arm.down = false;
			let bob = s.bob;
			if (stop) {
				bob = restart(s, tag);
				await reconnectHosts(s.alice, bob);
				await reconnectHosts(bob, s.carol);
				await settle();
			}
			bob.node.handleNewBlock(1);
			await turns(200);
			await settle();
			expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
			expect(
				bob.node
					.getChannelManager()
					.getChannel(s.context.outChannel)!
					.getFullState().localHtlcCounter
			).to.equal(1n);
			expect(s.asked).to.have.length(1);
			expect(s.told).to.deep.equal([]);
			fs.rmSync(s.directory, { recursive: true, force: true });
			restoreRandomness();
		}
	});

	it("keeps the link while its provider refuses the failure upstream of Carol's failure, then fails the payer back with it", async () => {
		const tag = 'aux-fwd-a2a-provider-refuses-fail';
		const s = await scene(tag, refuser);
		s.arm.down = true;
		expect(s.carol.node.cancelHeldHtlc(s.paymentHash)).to.equal(true);
		await settle();
		await settle();
		expect(refusals(s.bob, 'the failure of an HTLC')).to.have.length(1);
		expect(storedDecision(s.bob, s.context.inChannel)?.outcome).to.equal(
			'fail'
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		s.arm.down = false;
		s.bob.node.handleNewBlock(1);
		await turns(200);
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		expect(s.told).to.deep.equal([]);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('settles from its decision, and never fails, an incoming HTLC whose settle a preimage learned on the chain decided, when the forward is then failed upstream', async () => {
		const tag = 'aux-fwd-a2a-settle-stands';
		const s = await scene(tag, refuser);
		// A preimage of the hash learned on the chain (as from another part
		// of the same payment) while the provider refuses: the decision to
		// settle is written and the link stays.
		s.arm.down = true;
		const node = s.bob.node as unknown as {
			handleOnChainPreimageLearned: (
				paymentHash: Buffer,
				preimage: Buffer
			) => void;
			forwardedHtlcs: Map<string, { inChannelId: Buffer; inHtlcId: bigint }>;
			failForwardUpstream: (
				outKey: string,
				forward: { inChannelId: Buffer; inHtlcId: bigint },
				outChannelId: Buffer,
				outHtlcId: bigint,
				reason: Buffer,
				preWrapped?: boolean
			) => boolean;
		};
		node.handleOnChainPreimageLearned(s.paymentHash, s.preimage);
		await settle();
		expect(storedDecision(s.bob, s.context.inChannel)?.outcome).to.equal(
			'settle'
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);

		// The forward is then failed upstream, as when its outgoing leg's
		// failure turns irrevocable, with a provider that answers: the
		// incoming HTLC is settled from the decision that stands.
		s.arm.down = false;
		const [[outKey, forward]] = [...node.forwardedHtlcs];
		node.failForwardUpstream(
			outKey,
			forward,
			s.context.outChannel,
			0n,
			Buffer.alloc(256),
			true
		);
		await settle();
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('fails the payer back through the forward when the incoming expiry comes near after the outgoing leg failed, keeping the link while its provider refuses the failure', async () => {
		const tag = 'aux-fwd-a2a-timeout-refund';
		const s = await scene(tag, refuser);
		s.arm.down = true;
		expect(s.carol.node.cancelHeldHtlc(s.paymentHash)).to.equal(true);
		await settle();
		await settle();
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(linksInMemory(s.bob)).to.equal(1);

		// Within twice the safety margin of the incoming expiry, with the
		// outgoing leg failed: the refund goes up off the chain, through the
		// forward's own path, which keeps the link while it is refused.
		const expiry = s.bob.node.getAuxiliaryChannelInfo(s.context.inChannel)!
			.htlcs[0].cltvExpiry;
		const margin = (s.bob.node as unknown as { htlcSafetyMargin: number })
			.htlcSafetyMargin;
		s.bob.node.handleNewBlock(expiry - 2 * margin + 1);
		await turns(200);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(linksInMemory(s.bob)).to.equal(1);

		s.arm.down = false;
		s.bob.node.handleNewBlock(expiry - 2 * margin + 2);
		await turns(200);
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		expect(linksInMemory(s.bob)).to.equal(0);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('forwards between two asset channels with the same peer', async () => {
		const tag = 'aux-fwd-a2a-same-peer';
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const context = {} as IContext;
		const alice = assetHost(tag, 1, {
			valueIncomingHtlc: (incoming) =>
				incoming.auxiliaryAmount === undefined
					? undefined
					: incoming.auxiliaryAmount * MSAT_PER_UNIT
		});
		const bob = assetHost(
			tag,
			2,
			{
				prepareForward: (request): IAuxiliaryForwardTerms => {
					asked.push(request);
					return terms(request, context);
				}
			},
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		context.inChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.outChannel = await openAssetChannel(bob, alice, {
			tag: `${tag} out`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.alice = alice.node.getNodeId();
		context.carol = alice.node.getNodeId();
		await settle();
		const outAlias = bob.node
			.getChannelManager()
			.getChannel(context.outChannel)!
			.getFullState().scidAlias!;
		const invoice = alice.node.createInvoice({
			amountMsat: FORWARD_MSAT,
			description: tag
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: FIRST_HOP_SCID,
						amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(alice.node.getNodeId(), 'hex'),
						shortChannelId: outAlias,
						amountToForwardMsat: FORWARD_MSAT,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId: context.inChannel,
					wireAmountMsat: CARRIER_MSAT,
					customRecords: amountRecord(INCOMING_UNITS)
				}
			}
		);
		await settle();
		await settle();
		expect(asked).to.have.length(1);
		expect(
			bob.node
				.getChannelManager()
				.getChannel(context.outChannel)!
				.getFullState().localHtlcCounter
		).to.equal(1n);
		expect(bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
	});
});
