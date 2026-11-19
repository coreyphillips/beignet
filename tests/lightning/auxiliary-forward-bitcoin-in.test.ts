/**
 * Issue #2098, step 2: bitcoin in, asset out.
 *
 * With the switch for asset forwards on, a node in the middle forwards a
 * bitcoin HTLC out over an asset channel: when its host claims the short
 * channel id the onion names (the hint of an asset invoice made from one
 * of its quotes), and when the onion names the asset channel by its alias.
 * The host is asked once, after the node wrote that it asks and outside any
 * storage transaction. The outgoing HTLC carries the records and the
 * carrier the host made, and every check of the node's own still holds. A
 * host that answered with terms the node then refuses is told that the
 * outgoing leg was never offered; one that threw or answered undefined is
 * told nothing.
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
import {
	hasScidAliasChannelType,
	HtlcDirection
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	TEMPORARY_CHANNEL_FAILURE,
	UNKNOWN_NEXT_PEER
} from '../../src/lightning/onion/types';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	fixRandomness,
	openAssetChannel,
	reconnectHosts,
	restoreRandomness,
	withAssetForwards,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** The scid openReadyChannel gives the ordinary channel of a pair. */
const ORDINARY_SCID = Buffer.from('0001f40000010000', 'hex');

/** A short channel id no channel of Bob's has: one of his host's quotes. */
const QUOTE_SCID = hash('a quote of the middle node').subarray(0, 8);

/** What the payer pays Bob, and what Bob is asked to forward to Carol. */
const INCOMING_MSAT = 5_010_000n;
const FORWARD_MSAT = 5_000_000n;

interface IContext {
	/** Bob's asset channel with Carol. */
	assetChannel: Buffer;
	/** Alice's ordinary channel with Bob, on which the HTLC comes in. */
	incomingChannel: Buffer;
	carol: string;
	alice: string;
}

type Answer = (
	request: IAuxiliaryForwardRequest,
	context: IContext
) => IAuxiliaryForwardTerms | undefined;

/** The terms a host gives for a forward of 5,000 units over the asset channel. */
const units = (
	request: IAuxiliaryForwardRequest,
	context: IContext,
	extra: Partial<IAuxiliaryForwardTerms> = {}
): IAuxiliaryForwardTerms => ({
	...(request.outgoing === undefined
		? {
				outgoingChannel: {
					channelId: context.assetChannel,
					peerPubkey: context.carol
				}
		  }
		: {}),
	outgoingHtlc: {
		customRecords: amountRecord(5000n),
		wireAmountMsat: 354_000n
	},
	...extra
});

interface IOptions {
	/** The onion names a short channel id Bob has no channel for; else the asset channel's alias. */
	quote: boolean;
	/** Bob's host's prepareForward. Absent: the host supplies no forward hook. */
	answer?: Answer;
	/** What Alice pays Bob for the hop. */
	incomingMsat?: bigint;
	/** What Carol's host values a unit at, in millisatoshis. */
	carolMsatPerUnit?: bigint;
	/** The onion names the asset channel by its real short channel id. */
	realScid?: boolean;
	/**
	 * Bob's row of the incoming HTLC says he asks before he dispatches it, as
	 * after a stop between that write and keeping the answer.
	 */
	markedBefore?: boolean;
	/** The expiry the onion asks of Bob's outgoing HTLC. */
	forwardCltv?: number;
	/** Bob's bound on HTLCs in flight across his channels refuses the HTLC. */
	inFlightCap?: boolean;
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
	alice: PaymentStatus | undefined;
	failure: [number | undefined, number | undefined];
	carol: PaymentStatus | undefined;
	/** The asset HTLC as Carol's host saw it. */
	carolSaw: { wireAmountMsat?: bigint; units?: bigint; records?: string };
	/** HTLCs Bob offered on his asset channel. */
	offered: bigint;
	/** Bob's units on the asset channel, his and Carol's. */
	units: [bigint, bigint];
	links: number;
	forwards: number;
}

describe('a bitcoin HTLC forwarded out over an asset channel (issue #2098, step 2)', function () {
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
	 * Alice pays Carol's invoice of 5,000,000 msat through Bob, who holds an
	 * ordinary channel with Alice and an asset channel with Carol (9,000
	 * units his, 1,000 hers). Bob runs on SQLite.
	 */
	async function run(tag: string, options: IOptions): Promise<IResult> {
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const inTransaction: boolean[] = [];
		const markedBeforeAsk: boolean[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const hooks: string[] = [];
		const carolSaw: IResult['carolSaw'] = {};
		const context = {} as IContext;
		// Bob, once made: his hooks read his storage.
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
		const bob = assetHost(
			tag,
			2,
			{
				onHtlcResolved: (resolved) => {
					hooks.push(
						`onHtlcResolved:${resolved.direction}:${resolved.outcome}`
					);
				},
				...forwardHooks
			},
			{ sqlite: true }
		);
		made.bob = bob;
		const alice = assetHost(tag, 1, {});
		const carol = assetHost(tag, 3, {
			valueIncomingHtlc: (incoming) => {
				carolSaw.wireAmountMsat = incoming.wireAmountMsat;
				carolSaw.units = incoming.auxiliaryAmount;
				carolSaw.records = [...incoming.customRecords]
					.map(([type, value]) => `${type}:${value.toString('hex')}`)
					.join(',');
				return incoming.auxiliaryAmount === undefined
					? undefined
					: incoming.auxiliaryAmount * (options.carolMsatPerUnit ?? 1000n);
			}
		});
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
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
				expect(
					bob.node.getChannelManager().recordForwardAsk(channelId, htlcId)
				).to.equal(true);
				return dispatch(channelId, htlcId, ...rest);
			};
		}
		if (options.inFlightCap) {
			(
				bob.node as unknown as { maxTotalInFlightHtlcs: number }
			).maxTotalInFlightHtlcs = -1;
		}
		context.incomingChannel = openReadyChannel(alice.node, bob.node);
		context.assetChannel = await openAssetChannel(bob, carol, {
			tag: `${tag} out`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.carol = carol.node.getNodeId();
		context.alice = alice.node.getNodeId();
		const assetState = bob.node
			.getChannelManager()
			.getChannel(context.assetChannel)!
			.getFullState();
		if (options.realScid) {
			// The channel's type with option_scid_alias, and the real short
			// channel id a confirmed funding gives it (block 900,000,
			// transaction 7, output 0): BOLT 2 forbids forwarding over such a
			// channel by that id, so the node never put it in its map.
			const state = assetState as {
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
		const next = options.quote
			? QUOTE_SCID
			: options.realScid
			? assetState.shortChannelId!
			: bob.node.getAuxiliaryChannelInfo(context.assetChannel)!.shortChannelId!;
		await settle();

		const invoice = carol.node.createInvoice({
			amountMsat: FORWARD_MSAT,
			description: tag
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: ORDINARY_SCID,
						amountToForwardMsat: options.incomingMsat ?? INCOMING_MSAT,
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
			invoice.paymentSecret
		);
		await settle();

		const after = bob.node
			.getChannelManager()
			.getChannel(context.assetChannel)!
			.getFullState();
		return {
			context,
			paymentHash: invoice.paymentHash,
			asked,
			inTransaction,
			markedBeforeAsk,
			told,
			hooks,
			alice: alice.node.getPayment(invoice.paymentHash)?.status,
			failure: [
				alice.node.getPayment(invoice.paymentHash)?.failureCode,
				alice.node.getPayment(invoice.paymentHash)?.failureSourceIndex
			],
			carol: carol.node.getPayment(invoice.paymentHash)?.status,
			carolSaw,
			offered: after.localHtlcCounter,
			units: [
				after.auxiliaryState!.localBalance,
				after.auxiliaryState!.remoteBalance
			],
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
			wireAmountMsat: 354_000n,
			units: 5000n,
			records: `65536:${amountRecord(5000n).get(65536n)!.toString('hex')}`
		});
		expect(result.offered).to.equal(1n);
		expect(result.units).to.deep.equal([4000n, 6000n]);
		// Asked once, after the node wrote that it asks, outside any storage
		// transaction; told nothing, since nothing was refused.
		expect(result.asked).to.have.length(1);
		expect(result.inTransaction).to.deep.equal([false]);
		expect(result.markedBeforeAsk).to.deep.equal([true]);
		expect(result.told).to.deep.equal([]);
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.OFFERED}:fulfilled`
		);
		// The link went with the settle. An asset forward is not recorded in
		// the forwarding history yet: its carrier is not what it was worth.
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
	}

	/** The checks of a forward refused at Bob before anything was offered. */
	function refused(result: IResult, failureCode: number): void {
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.failure).to.deep.equal([failureCode, 0]);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(0n);
		expect(result.units).to.deep.equal([9000n, 1000n]);
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
	}

	it("to a short channel id the host claims: asked once with the request as the contract gives it, and paid with the host's records and carrier", async () => {
		const result = await run('aux-fwd-btc-quote', {
			quote: true,
			answer: (request, context) => units(request, context)
		});
		forwarded(result);
		const [request] = result.asked;
		expect(request.paymentHash.equals(result.paymentHash)).to.equal(true);
		expect(
			request.incoming.channelId.equals(result.context.incomingChannel)
		).to.equal(true);
		expect(request.incoming).to.deep.include({
			peerPubkey: result.context.alice,
			htlcId: 0n,
			wireAmountMsat: INCOMING_MSAT,
			auxiliaryChannel: false
		});
		expect(request.incoming.auxiliaryAmount).to.equal(undefined);
		expect(request.incoming.customRecords.size).to.equal(0);
		expect(request.shortChannelId.equals(QUOTE_SCID)).to.equal(true);
		expect(request.amountToForwardMsat).to.equal(FORWARD_MSAT);
		expect(request.outgoingCltvExpiry).to.equal(40);
		expect(request.outgoing).to.equal(undefined);
	});

	it('over the asset channel the onion names by its alias: the request names it, and the terms carry the outgoing HTLC alone', async () => {
		const result = await run('aux-fwd-btc-alias', {
			quote: false,
			answer: (request, context) => units(request, context)
		});
		forwarded(result);
		const outgoing = result.asked[0].outgoing!;
		expect(outgoing.channelId.equals(result.context.assetChannel)).to.equal(
			true
		);
		expect(outgoing).to.deep.include({
			peerPubkey: result.context.carol,
			auxiliaryChannel: true
		});
	});

	it('a failure downstream fails the payer back, and the link goes with it', async () => {
		const result = await run('aux-fwd-btc-downstream', {
			quote: true,
			answer: (request, context) => units(request, context),
			// Carol's host values the units under her invoice.
			carolMsatPerUnit: 900n
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.failure[1]).to.equal(1);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(1n);
		expect(result.units).to.deep.equal([9000n, 1000n]);
		expect(result.links).to.equal(0);
		expect(result.asked).to.have.length(1);
		// It was offered, so the host is not told it never was.
		expect(result.told).to.deep.equal([]);
	});

	interface IRefusal {
		name: string;
		quote: boolean;
		answer: Answer;
		failure: number;
		/** Whether the host answered with terms, and is told never-offered. */
		told: boolean;
		/** The channel the host is told of, when told. */
		channel?: 'asset' | 'incoming' | 'none';
		incomingMsat?: bigint;
	}

	const REFUSALS: IRefusal[] = [
		{
			name: 'a throw',
			quote: true,
			answer: (): IAuxiliaryForwardTerms => {
				throw new Error('no such quote');
			},
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: false
		},
		{
			name: 'a promise',
			quote: true,
			answer: (request, context) =>
				Promise.resolve(
					units(request, context)
				) as unknown as IAuxiliaryForwardTerms,
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: false
		},
		{
			name: 'undefined, for a short channel id the node has no channel for',
			quote: true,
			answer: () => undefined,
			failure: UNKNOWN_NEXT_PEER,
			told: false
		},
		{
			name: 'undefined, for the asset channel the onion names',
			quote: false,
			answer: () => undefined,
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: false
		},
		{
			name: 'a field the forward does not call for',
			quote: false,
			answer: (request, context) =>
				units(request, context, { incomingValueMsat: 5_010_000n }),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'asset'
		},
		{
			name: 'no channel, for a short channel id the node has no channel for',
			quote: true,
			answer: () => ({
				outgoingHtlc: {
					customRecords: amountRecord(5000n),
					wireAmountMsat: 354_000n
				}
			}),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'none'
		},
		{
			name: 'a channel that is not an asset channel of the node',
			quote: true,
			answer: (request, context) => ({
				...units(request, context),
				outgoingChannel: {
					channelId: context.incomingChannel,
					peerPubkey: context.alice
				}
			}),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'incoming'
		},
		{
			name: 'records under the custom range',
			quote: true,
			answer: (request, context) => ({
				...units(request, context),
				outgoingHtlc: {
					customRecords: new Map([[1n, Buffer.from('00', 'hex')]]),
					wireAmountMsat: 354_000n
				}
			}),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'asset'
		},
		{
			name: 'a carrier under the dust limit',
			quote: true,
			answer: (request, context) => ({
				...units(request, context),
				outgoingHtlc: {
					customRecords: amountRecord(5000n),
					wireAmountMsat: 100_000n
				}
			}),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'asset'
		},
		{
			name: 'more units than the node holds on the channel',
			quote: true,
			answer: (request, context) => ({
				...units(request, context),
				outgoingHtlc: {
					customRecords: amountRecord(20_000n),
					wireAmountMsat: 354_000n
				}
			}),
			failure: TEMPORARY_CHANNEL_FAILURE,
			told: true,
			channel: 'asset'
		},
		{
			name: "an incoming HTLC that does not pay the outgoing channel's fee",
			quote: true,
			answer: (request, context) => units(request, context),
			incomingMsat: FORWARD_MSAT,
			failure: FEE_INSUFFICIENT,
			told: true,
			channel: 'asset'
		}
	];

	for (const refusal of REFUSALS) {
		it(`refuses ${refusal.name} before anything is offered, and tells the host only when it answered with terms`, async () => {
			const result = await run(
				`aux-fwd-btc-refused-${REFUSALS.indexOf(refusal)}`,
				{
					quote: refusal.quote,
					answer: refusal.answer,
					incomingMsat: refusal.incomingMsat
				}
			);
			refused(result, refusal.failure);
			expect(result.asked).to.have.length(1);
			if (!refusal.told) {
				expect(result.told).to.deep.equal([]);
				return;
			}
			expect(result.told).to.have.length(1);
			const [told] = result.told;
			expect(told).to.deep.include({
				incomingHtlcId: 0n,
				leg: 'outgoing',
				outcome: 'never-offered',
				onChain: false
			});
			expect(told.paymentHash.equals(result.paymentHash)).to.equal(true);
			expect(
				told.incomingChannelId.equals(result.context.incomingChannel)
			).to.equal(true);
			expect(told.customRecords.size).to.equal(0);
			const channel =
				refusal.channel === 'asset'
					? result.context.assetChannel
					: refusal.channel === 'incoming'
					? result.context.incomingChannel
					: undefined;
			if (channel) expect(told.channelId?.equals(channel)).to.equal(true);
			else expect(told.channelId).to.equal(undefined);
		});
	}

	it('asks nothing for the real short channel id of an asset channel whose type has option_scid_alias, and fails it as before', async () => {
		const result = await run('aux-fwd-btc-real-scid', {
			quote: false,
			realScid: true,
			answer: (request, context) => units(request, context)
		});
		refused(result, UNKNOWN_NEXT_PEER);
		expect(result.asked).to.deep.equal([]);
		expect(result.told).to.deep.equal([]);
	});

	for (const quote of [true, false]) {
		it(`asks nothing of a host without prepareForward, and refuses as before (${
			quote
				? 'a short channel id the node has no channel for'
				: 'the asset channel the onion names'
		})`, async () => {
			const result = await run(`aux-fwd-btc-no-hook-${quote}`, { quote });
			refused(result, quote ? UNKNOWN_NEXT_PEER : TEMPORARY_CHANNEL_FAILURE);
			expect(result.asked).to.deep.equal([]);
		});
	}
	it('asks again about an HTLC it had marked as asked before a stop, while the forward passes the checks made before the ask', async () => {
		const result = await run('aux-fwd-btc-marked-asks', {
			quote: false,
			markedBefore: true,
			answer: (request, context) => units(request, context)
		});
		forwarded(result);
	});

	it('tells the host the outgoing leg was never offered when a check before the ask refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-btc-marked-refused', {
			quote: false,
			markedBefore: true,
			// The incoming expiry is 20 blocks over the outgoing one, under
			// the asset channel's CLTV delta of 40.
			forwardCltv: 220,
			answer: (request, context) => units(request, context)
		});
		refused(result, INCORRECT_CLTV_EXPIRY);
		expect(result.asked).to.deep.equal([]);
		expect(result.told).to.have.length(1);
		expect(result.told[0]).to.deep.include({
			incomingHtlcId: 0n,
			leg: 'outgoing',
			outcome: 'never-offered',
			onChain: false
		});
		expect(
			result.told[0].channelId?.equals(result.context.assetChannel)
		).to.equal(true);
	});

	it('tells the host the outgoing leg was never offered when the bound on HTLCs in flight refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-btc-marked-cap', {
			quote: false,
			markedBefore: true,
			inFlightCap: true,
			answer: (request, context) => units(request, context)
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.offered).to.equal(0n);
		expect(result.units).to.deep.equal([9000n, 1000n]);
		expect(result.asked).to.deep.equal([]);
		expect(result.told).to.have.length(1);
		expect(result.told[0]).to.deep.include({
			incomingHtlcId: 0n,
			leg: 'outgoing',
			outcome: 'never-offered',
			onChain: false
		});
		// Refused before the node looked for the next hop: no channel is named.
		expect(result.told[0].channelId).to.equal(undefined);
	});

	it('tells a host nothing about an HTLC it was never asked about, when a check before the ask refuses it', async () => {
		const result = await run('aux-fwd-btc-unmarked-refused', {
			quote: false,
			forwardCltv: 220,
			answer: (request, context) => units(request, context)
		});
		refused(result, INCORRECT_CLTV_EXPIRY);
		expect(result.asked).to.deep.equal([]);
		expect(result.told).to.deep.equal([]);
	});

	it('asks once: a reestablish and a restart with the forward in flight ask nothing again, and the payment still settles', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'aux-fwd-btc-restart-')
		);
		const bobFile = path.join(directory, 'bob.sqlite');
		const tag = 'aux-fwd-btc-restart';
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const context = {} as IContext;
		const bobHooks = (): Partial<IAuxiliaryChannelConfig> => ({
			prepareForward: (request): IAuxiliaryForwardTerms => {
				asked.push(request);
				return units(request, context);
			},
			onForwardLegResolved: (resolution): void => {
				told.push(resolution);
			}
		});
		const alice = assetHost(tag, 1, {});
		const bob = assetHost(tag, 2, bobHooks(), { sqlitePath: bobFile });
		const carol = assetHost(tag, 3, {
			valueIncomingHtlc: (incoming) =>
				incoming.auxiliaryAmount === undefined
					? undefined
					: incoming.auxiliaryAmount * 1000n
		});
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		context.incomingChannel = openReadyChannel(alice.node, bob.node);
		context.assetChannel = await openAssetChannel(bob, carol, {
			tag: `${tag} out`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.carol = carol.node.getNodeId();
		context.alice = alice.node.getNodeId();
		await settle();

		// Carol holds the payment, so the forward stays in flight.
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
						shortChannelId: ORDINARY_SCID,
						amountToForwardMsat: INCOMING_MSAT,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
						shortChannelId: QUOTE_SCID,
						amountToForwardMsat: FORWARD_MSAT,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret
		);
		await settle();
		expect(asked).to.have.length(1);
		expect(bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// A reestablish of both of Bob's channels asks nothing.
		await reconnectHosts(alice, bob);
		await reconnectHosts(bob, carol);
		expect(asked).to.have.length(1);

		// Bob stops and starts again from his storage: the forward is kept
		// with its link, so nothing is asked again.
		bob.node.destroy();
		bob.storage!.close();
		const restarted = assetHost(tag, 2, bobHooks(), { sqlitePath: bobFile });
		hosts.push(restarted);
		connectHosts(alice, restarted);
		connectHosts(restarted, carol);
		await reconnectHosts(alice, restarted);
		await reconnectHosts(restarted, carol);
		await settle();
		expect(asked).to.have.length(1);
		expect(restarted.storage!.loadAllForwardedHtlcs()).to.have.length(1);

		expect(carol.node.settleHeldHtlc(paymentHash, preimage)).to.equal(true);
		await settle();
		await settle();
		expect(alice.node.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(restarted.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		const state = restarted.node
			.getChannelManager()
			.getChannel(context.assetChannel)!
			.getFullState();
		expect([
			state.auxiliaryState!.localBalance,
			state.auxiliaryState!.remoteBalance
		]).to.deep.equal([4000n, 6000n]);
		expect(told).to.deep.equal([]);
		fs.rmSync(directory, { recursive: true, force: true });
	});
});
