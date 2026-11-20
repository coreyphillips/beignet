/**
 * Issue #2098, step 3: asset in, bitcoin out.
 *
 * With the switch for asset forwards on, a node in the middle forwards an
 * HTLC that came in on an asset channel carrying units over an ordinary
 * channel the onion names, when its host values the incoming HTLC at no
 * less than the amount to forward and the node's fee. The host is asked
 * once, after the node wrote that it asks and outside any storage
 * transaction, and the carrier of the incoming HTLC is never taken for what
 * it is worth. The node writes its decision for the incoming HTLC with the
 * asset channel's row once it knows how the outgoing one ended, and the link
 * to the outgoing HTLC goes only with a removal the asset channel takes, so
 * that a restart never forwards the HTLC a second time and a claim on the
 * chain can be made by that decision.
 */

import { expect } from 'chai';
import type { IForwardingEvent } from '../../src/lightning/storage/types';
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
import { OutputType } from '../../src/lightning/chain/types';
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
	plainHost,
	reconnectHosts,
	restoreRandomness,
	turns,
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

/** The scid a route's first hop names; Alice's asset payment goes over its channel. */
const ORDINARY_SCID = Buffer.from('0001f40000010000', 'hex');

/** A short channel id no channel of Bob's has. */
const QUOTE_SCID = hash('an id the middle node does not know').subarray(0, 8);

/** The units Alice sends Bob, and what Bob's host values each at. */
const INCOMING_UNITS = 5010n;
const MSAT_PER_UNIT = 1000n;
/** What Alice's onion asks Bob to forward to Carol. */
const FORWARD_MSAT = 5_000_000n;
/** The bitcoin Alice's asset HTLC carries on the wire. */
const CARRIER_MSAT = 354_000n;

interface IContext {
	/** Alice's asset channel with Bob, on which the HTLC comes in. */
	assetChannel: Buffer;
	/** Bob's ordinary channel with Carol, over which it goes on. */
	outChannel: Buffer;
	alice: string;
	carol: string;
}

type Answer = (
	request: IAuxiliaryForwardRequest,
	context: IContext
) => IAuxiliaryForwardTerms | undefined;

/** The terms of a host that values each unit at MSAT_PER_UNIT. */
const valued = (
	request: IAuxiliaryForwardRequest,
	extra: Record<string, unknown> = {}
): IAuxiliaryForwardTerms =>
	({
		incomingValueMsat: request.incoming.auxiliaryAmount! * MSAT_PER_UNIT,
		...extra
	}) as IAuxiliaryForwardTerms;

/**
 * What the onion names as Bob's next hop: the ordinary channel by Bob's own
 * alias or by the one Carol gave it (the channel has no real id here, and
 * Bob's map holds both aliases), an id Bob has no channel for, Bob's asset
 * channel with Alice (the one the HTLC came in on), an id the JIT receive
 * minted, or the ordinary channel's real id once its type has
 * option_scid_alias.
 */
type Next = 'alias' | 'peer-alias' | 'unknown' | 'asset' | 'jit' | 'real';

interface IOptions {
	/** Bob's host's prepareForward. Absent: the host supplies no forward hook. */
	answer?: Answer;
	/** The next hop the onion names; Bob's own alias of the out channel when left out. */
	next?: Next;
	/** What the onion asks Bob to forward. */
	forwardMsat?: bigint;
	/** What Carol's invoice asks, when it is not what Bob forwards. */
	invoiceMsat?: bigint;
	/** The expiry the onion asks of Bob's outgoing HTLC. */
	forwardCltv?: number;
	/**
	 * Bob's row of the incoming HTLC says he asks before he dispatches it, as
	 * after a stop between that write and keeping the answer.
	 */
	markedBefore?: boolean;
	/**
	 * Bob cannot write the mark that his host took the forward
	 * (ChannelManager.recordForwardTaken), as when the row of the incoming
	 * channel cannot be written after the host answered.
	 */
	takenUnwritten?: boolean;
	/** Bob's bound on HTLCs in flight across his channels refuses the HTLC. */
	inFlightCap?: boolean;
	/** A delegated settlement slot of Bob's holds the payment hash. */
	fforSlot?: boolean;
	/** The switch for asset forwards is off. */
	switchOff?: boolean;
}

interface IResult {
	context: IContext;
	paymentHash: Buffer;
	/** The short channel id the onion named. */
	next: Buffer;
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
	/** The HTLC Carol received, as she recorded it. */
	carolMsat: bigint | undefined;
	/** HTLCs Bob offered on his channel with Carol. */
	offered: bigint;
	/** Bob's bitcoin on his channel with Carol, before and after. */
	outBalance: [bigint, bigint];
	/** Bob's units on the asset channel, his and Alice's. */
	units: [bigint, bigint];
	links: number;
	forwards: number;
	/** Bob's forwarding history (issue #2098, step 7). */
	rows: IForwardingEvent[];
}

describe('an asset HTLC forwarded out over an ordinary channel (issue #2098, step 3)', function () {
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
	 * Bob holds an ordinary channel with Carol and runs on SQLite.
	 */
	async function run(tag: string, options: IOptions): Promise<IResult> {
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const inTransaction: boolean[] = [];
		const markedBeforeAsk: boolean[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const hooks: string[] = [];
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
		const carol = plainHost(tag, 3);
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		context.assetChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.outChannel = openReadyChannel(bob.node, carol.node);
		context.alice = alice.node.getNodeId();
		context.carol = carol.node.getNodeId();
		await settle();

		const outBefore = bob.node
			.getChannelManager()
			.getChannel(context.outChannel)!
			.getFullState();
		// The state is live: what it holds now is read now.
		const outBalanceBefore = outBefore.localBalanceMsat;
		if (options.next === 'real') {
			// The ordinary channel's type with option_scid_alias, and the real
			// short channel id a confirmed funding gives it: BOLT 2 forbids
			// forwarding over such a channel by that id, so the node never put
			// it in its map.
			const state = outBefore as {
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
		const next = ((): Buffer => {
			switch (options.next ?? 'alias') {
				case 'alias':
					expect(
						outBefore.scidAlias,
						'the out channel has an alias'
					).to.not.equal(undefined);
					return outBefore.scidAlias!;
				case 'peer-alias':
					expect(
						outBefore.remoteScidAlias,
						'the out channel has an alias of the peer'
					).to.not.equal(undefined);
					return outBefore.remoteScidAlias!;
				case 'unknown':
				case 'jit':
					return QUOTE_SCID;
				case 'asset':
					return bob.node.getAuxiliaryChannelInfo(context.assetChannel)!
						.shortChannelId!;
				case 'real':
					return outBefore.shortChannelId!;
			}
		})();

		const forwardMsat = options.forwardMsat ?? FORWARD_MSAT;
		const invoice = carol.node.createInvoice({
			amountMsat: options.invoiceMsat ?? forwardMsat,
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
				expect(
					bob.node.getChannelManager().recordForwardAsk(channelId, htlcId)
				).to.equal(true);
				return dispatch(channelId, htlcId, ...rest);
			};
		}
		if (options.takenUnwritten) {
			(
				bob.node.getChannelManager() as unknown as {
					recordForwardTaken: () => boolean;
				}
			).recordForwardTaken = (): boolean => false;
		}
		if (options.inFlightCap) {
			(
				bob.node as unknown as { maxTotalInFlightHtlcs: number }
			).maxTotalInFlightHtlcs = -1;
		}
		if (options.fforSlot) {
			const manager = bob.node.getChannelManager() as unknown as {
				fforFindDelegatedSlot: (paymentHash: Buffer) => unknown;
			};
			manager.fforFindDelegatedSlot = (paymentHash): unknown =>
				paymentHash.equals(invoice.paymentHash)
					? {
							channelId: context.outChannel,
							record: {},
							entry: { k: 0 }
					  }
					: undefined;
		}
		if (options.switchOff) auxiliaryForwards.enabled = false;
		try {
			alice.node.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
							shortChannelId: ORDINARY_SCID,
							amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
							outgoingCltvValue: 240
						},
						{
							pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
							shortChannelId: next,
							amountToForwardMsat: forwardMsat,
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
						channelId: context.assetChannel,
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

		const outAfter = bob.node
			.getChannelManager()
			.getChannel(context.outChannel)!
			.getFullState();
		const assetAfter = bob.node
			.getChannelManager()
			.getChannel(context.assetChannel)!
			.getFullState();
		return {
			context,
			paymentHash: invoice.paymentHash,
			next,
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
			carolMsat: carol.node.getPayment(invoice.paymentHash)?.amountMsat,
			offered: outAfter.localHtlcCounter,
			outBalance: [outBalanceBefore, outAfter.localBalanceMsat],
			units: [
				assetAfter.auxiliaryState!.localBalance,
				assetAfter.auxiliaryState!.remoteBalance
			],
			links: bob.storage!.loadAllForwardedHtlcs().length,
			forwards: bob.storage!.listForwardingEvents().length,
			rows: bob.storage!.listForwardingEvents()
		};
	}

	/** The ends of the forward's legs the host was told, as `leg:outcome` (step 5). */
	const legEnds = (told: IAuxiliaryForwardLegResolution[]): string[] =>
		told.map((end) => `${end.leg}:${end.outcome}`).sort();
	/** The never-offered end the host was told, beside its incoming leg's failure. */
	const neverOfferedOf = (
		told: IAuxiliaryForwardLegResolution[]
	): IAuxiliaryForwardLegResolution =>
		told.find((end) => end.outcome === 'never-offered')!;

	/** The checks of a forward that went through. */
	function forwarded(result: IResult): void {
		expect(result.alice).to.equal(PaymentStatus.COMPLETED);
		expect(result.carol).to.equal(PaymentStatus.COMPLETED);
		// Carol was paid an ordinary HTLC of the amount to forward, out of
		// Bob's bitcoin, and Bob holds the units Alice sent.
		expect(result.carolMsat).to.equal(FORWARD_MSAT);
		expect(result.offered).to.equal(1n);
		expect(result.outBalance[0] - result.outBalance[1]).to.equal(FORWARD_MSAT);
		expect(result.units).to.deep.equal([
			1000n + INCOMING_UNITS,
			9000n - INCOMING_UNITS
		]);
		// Asked once, after the node wrote that it asks, outside any storage
		// transaction; told how each leg ended (step 5): the asset leg it
		// came in on, with its units and records, and the bitcoin leg. The
		// hook of an HTLC that ends at the node is not asked about a forward.
		expect(result.asked).to.have.length(1);
		expect(result.inTransaction).to.deep.equal([false]);
		expect(result.markedBeforeAsk).to.deep.equal([true]);
		expect(legEnds(result.told)).to.deep.equal([
			'incoming:fulfilled',
			'outgoing:fulfilled'
		]);
		const incoming = result.told.find((end) => end.leg === 'incoming')!;
		expect(incoming).to.deep.include({
			incomingHtlcId: 0n,
			htlcId: 0n,
			auxiliaryAmount: INCOMING_UNITS,
			onChain: false
		});
		expect(incoming.customRecords.size).to.equal(1);
		const outgoing = result.told.find((end) => end.leg === 'outgoing')!;
		expect(outgoing.auxiliaryAmount).to.equal(undefined);
		expect(outgoing.customRecords.size).to.equal(0);
		expect(result.valuedHere).to.equal(0);
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.RECEIVED}:fulfilled`
		);
		// The link went with the settle. Issue #2098, step 7: the forward is
		// in Bob's forwarding history, marked auxiliary, at what each leg was
		// worth (auxiliary-forward-history.test.ts checks each field).
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(1);
		const row = result.rows[0];
		expect(row.auxiliary).to.equal(true);
		expect(row.amountOutMsat).to.equal(result.asked[0].amountToForwardMsat);
		expect(row.feeMsat).to.equal(row.amountInMsat - row.amountOutMsat);
		expect(row.nextHopScid).to.equal(
			result.asked[0].shortChannelId.toString('hex')
		);
		expect(row.inAuxiliaryAmount !== undefined).to.equal(true);
		expect(row.outAuxiliaryAmount !== undefined).to.equal(false);
	}

	/** The checks of a forward refused at Bob before anything was offered. */
	function refused(result: IResult, failureCode: number): void {
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.failure).to.deep.equal([failureCode, 0]);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(0n);
		expect(result.outBalance[1]).to.equal(result.outBalance[0]);
		expect(result.units).to.deep.equal([1000n, 9000n]);
		expect(result.valuedHere).to.equal(0);
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
	}

	/** The one never-offered a host is told when it answered with terms. */
	function toldNeverOffered(result: IResult, outChannel?: Buffer): void {
		// Beside the incoming leg's own end: it was failed back (step 5).
		expect(legEnds(result.told)).to.deep.equal([
			'incoming:failed',
			'outgoing:never-offered'
		]);
		const told = neverOfferedOf(result.told);
		expect(told).to.deep.include({
			incomingHtlcId: 0n,
			leg: 'outgoing',
			outcome: 'never-offered',
			onChain: false
		});
		expect(told.paymentHash.equals(result.paymentHash)).to.equal(true);
		expect(told.incomingChannelId.equals(result.context.assetChannel)).to.equal(
			true
		);
		if (outChannel) expect(told.channelId?.equals(outChannel)).to.equal(true);
	}

	it('over the ordinary channel the onion names by its alias: asked once with the request as the contract gives it, and Carol is paid in bitcoin', async () => {
		const result = await run('aux-fwd-in-alias', {
			answer: (request) => valued(request)
		});
		forwarded(result);
		const [request] = result.asked;
		expect(request.paymentHash.equals(result.paymentHash)).to.equal(true);
		expect(
			request.incoming.channelId.equals(result.context.assetChannel)
		).to.equal(true);
		// The incoming HTLC as it is: its carrier, its units and its records.
		expect(request.incoming).to.deep.include({
			peerPubkey: result.context.alice,
			htlcId: 0n,
			wireAmountMsat: CARRIER_MSAT,
			auxiliaryAmount: INCOMING_UNITS,
			auxiliaryChannel: true
		});
		expect(request.incoming.cltvExpiry).to.be.a('number');
		expect(request.incoming.cltvExpiry).to.be.greaterThan(
			request.outgoingCltvExpiry
		);
		expect(
			[...request.incoming.customRecords].map(
				([type, value]) => `${type}:${value.toString('hex')}`
			)
		).to.deep.equal(
			[...amountRecord(INCOMING_UNITS)].map(
				([type, value]) => `${type}:${value.toString('hex')}`
			)
		);
		expect(request.shortChannelId.equals(result.next)).to.equal(true);
		expect(request.amountToForwardMsat).to.equal(FORWARD_MSAT);
		expect(request.outgoingCltvExpiry).to.equal(40);
		expect(
			request.outgoing!.channelId.equals(result.context.outChannel)
		).to.equal(true);
		expect(request.outgoing).to.deep.include({
			peerPubkey: result.context.carol,
			auxiliaryChannel: false
		});
	});

	it('over the ordinary channel the onion names by the alias its peer gave it', async () => {
		const result = await run('aux-fwd-in-peer-alias', {
			next: 'peer-alias',
			answer: (request) => valued(request)
		});
		forwarded(result);
		expect(
			result.asked[0].outgoing!.channelId.equals(result.context.outChannel)
		).to.equal(true);
	});

	it("a failure downstream fails the payer back with the downstream's own failure, the link goes with it, and the host is not told the leg was never offered", async () => {
		const result = await run('aux-fwd-in-downstream', {
			answer: (request) => valued(request),
			// Carol's invoice asks more than Bob forwards: she refuses it.
			invoiceMsat: FORWARD_MSAT + 1_000_000n
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		// The failure is Carol's, relayed as she made it.
		expect(result.failure[1]).to.equal(1);
		expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
		expect(result.offered).to.equal(1n);
		expect(result.outBalance[1]).to.equal(result.outBalance[0]);
		expect(result.units).to.deep.equal([1000n, 9000n]);
		expect(result.asked).to.have.length(1);
		expect(result.links).to.equal(0);
		expect(result.forwards).to.equal(0);
		expect(result.hooks).to.include(
			`onHtlcResolved:${HtlcDirection.RECEIVED}:failed`
		);
		// It was offered, so the host is not told it never was; each leg
		// ended failed (step 5).
		expect(legEnds(result.told)).to.deep.equal([
			'incoming:failed',
			'outgoing:failed'
		]);
	});

	interface INotAsked {
		name: string;
		options: IOptions;
		failure: number;
	}

	const NOT_ASKED: INotAsked[] = [
		{
			// Asset in and asset out goes between two asset channels (step 4).
			name: 'the asset channel the HTLC came in on',
			options: { next: 'asset', answer: (request) => valued(request) },
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'a short channel id the JIT receive minted',
			options: { next: 'jit', answer: (request) => valued(request) },
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'the real short channel id of an ordinary channel whose type has option_scid_alias',
			options: { next: 'real', answer: (request) => valued(request) },
			failure: UNKNOWN_NEXT_PEER
		},
		{
			name: 'a host without prepareForward',
			options: {},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'the switch for asset forwards off',
			options: { switchOff: true, answer: (request) => valued(request) },
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: 'an outgoing channel that cannot take the HTLC',
			options: {
				// More than Bob holds on his channel with Carol.
				forwardMsat: 2_000_000_000n,
				answer: (request) => valued(request)
			},
			failure: TEMPORARY_CHANNEL_FAILURE
		},
		{
			name: "an incoming expiry short of the outgoing channel's CLTV delta",
			options: {
				// 20 blocks over the outgoing expiry, under the policy's delta.
				forwardCltv: 220,
				answer: (request) => valued(request)
			},
			failure: INCORRECT_CLTV_EXPIRY
		},
		{
			name: 'a payment hash a delegated settlement slot of the node holds',
			options: { fforSlot: true, answer: (request) => valued(request) },
			failure: TEMPORARY_CHANNEL_FAILURE
		}
	];

	for (const notAsked of NOT_ASKED) {
		it(`asks nothing and refuses as before for ${notAsked.name}`, async () => {
			const result = await run(
				`aux-fwd-in-not-asked-${NOT_ASKED.indexOf(notAsked)}`,
				notAsked.options
			);
			refused(result, notAsked.failure);
			expect(result.asked).to.deep.equal([]);
			expect(result.told).to.deep.equal([]);
		});
	}

	interface IRefusal {
		name: string;
		answer: Answer;
		/** Whether the host answered with terms, and is told never-offered. */
		told: boolean;
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
			answer: (request) =>
				Promise.resolve(valued(request)) as unknown as IAuxiliaryForwardTerms,
			told: false
		},
		{
			name: 'undefined',
			answer: () => undefined,
			told: false
		},
		{
			name: 'a field the forward does not call for',
			answer: (request) =>
				valued(request, {
					outgoingHtlc: {
						customRecords: amountRecord(5000n),
						wireAmountMsat: CARRIER_MSAT
					}
				}),
			told: true
		},
		{
			name: 'no value',
			answer: () => ({}),
			told: true
		},
		{
			name: 'a value of zero',
			answer: () => ({ incomingValueMsat: 0n }),
			told: true
		},
		{
			name: 'a value over a u64',
			answer: () => ({ incomingValueMsat: 1n << 64n }),
			told: true
		},
		{
			name: 'a value that is not a bigint',
			answer: () =>
				({ incomingValueMsat: 5_010_000 }) as unknown as IAuxiliaryForwardTerms,
			told: true
		},
		{
			name: "a value that does not cover the amount to forward and the node's fee",
			answer: () => ({ incomingValueMsat: FORWARD_MSAT }),
			told: true
		}
	];

	for (const refusal of REFUSALS) {
		it(`refuses ${refusal.name} with temporary_channel_failure before anything is offered, and tells the host only when it answered with terms`, async () => {
			const result = await run(
				`aux-fwd-in-refused-${REFUSALS.indexOf(refusal)}`,
				{ answer: refusal.answer }
			);
			// Never fee_insufficient: that would quote the carrier as what the
			// incoming HTLC is worth.
			refused(result, TEMPORARY_CHANNEL_FAILURE);
			expect(result.asked).to.have.length(1);
			if (refusal.told) {
				toldNeverOffered(result, result.context.outChannel);
				expect(neverOfferedOf(result.told).customRecords.size).to.equal(0);
			} else {
				expect(result.told).to.deep.equal([]);
			}
		});
	}

	it("asks about a short channel id the node has no channel for, as a quote's that leads to an asset channel (step 4), and refuses terms that name none, telling the host", async () => {
		const result = await run('aux-fwd-in-quote-terms', {
			next: 'unknown',
			answer: (request) => valued(request)
		});
		refused(result, TEMPORARY_CHANNEL_FAILURE);
		expect(result.asked).to.have.length(1);
		expect(result.asked[0].outgoing).to.equal(undefined);
		toldNeverOffered(result);
		expect(neverOfferedOf(result.told).channelId).to.equal(undefined);
	});

	it('asks again about an HTLC it had marked as asked before a stop, while the forward passes the checks made before the ask', async () => {
		const result = await run('aux-fwd-in-marked-asks', {
			markedBefore: true,
			answer: (request) => valued(request)
		});
		forwarded(result);
	});

	it('tells the host the outgoing leg was never offered when a check before the ask refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-in-marked-refused', {
			markedBefore: true,
			forwardCltv: 220,
			answer: (request) => valued(request)
		});
		refused(result, INCORRECT_CLTV_EXPIRY);
		expect(result.asked).to.deep.equal([]);
		toldNeverOffered(result, result.context.outChannel);
	});

	it('tells the host the outgoing leg was never offered when the mark that it took the forward cannot be written', async () => {
		const result = await run('aux-fwd-in-taken-unwritten', {
			takenUnwritten: true,
			answer: (request) => valued(request)
		});
		refused(result, TEMPORARY_CHANNEL_FAILURE);
		expect(result.asked).to.have.length(1);
		toldNeverOffered(result, result.context.outChannel);
	});

	it('tells the host the outgoing leg was never offered when the bound on HTLCs in flight refuses an HTLC it had marked as asked before a stop', async () => {
		const result = await run('aux-fwd-in-marked-cap', {
			markedBefore: true,
			inFlightCap: true,
			answer: (request) => valued(request)
		});
		expect(result.alice).to.equal(PaymentStatus.FAILED);
		expect(result.offered).to.equal(0n);
		expect(result.units).to.deep.equal([1000n, 9000n]);
		expect(result.asked).to.deep.equal([]);
		toldNeverOffered(result);
		expect(neverOfferedOf(result.told).channelId).to.equal(undefined);
	});

	it('tells a host nothing about an HTLC it was never asked about, when a check refuses it', async () => {
		const capped = await run('aux-fwd-in-unmarked-cap', {
			inFlightCap: true,
			answer: (request) => valued(request)
		});
		expect(capped.alice).to.equal(PaymentStatus.FAILED);
		expect(capped.asked).to.deep.equal([]);
		expect(capped.told).to.deep.equal([]);
	});

	/**
	 * Alice, Bob and Carol as in run(), with Bob on a SQLite file so he can
	 * stop and start again, and Carol holding the payment on a hold invoice
	 * so the forward stays in flight until the test settles it.
	 */
	async function scene(
		tag: string,
		bobExtra: (arm: { down: boolean }) => Partial<IAuxiliaryChannelConfig>
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
		arm: { down: boolean };
		preimage: Buffer;
		paymentHash: Buffer;
	}> {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), `${tag}-`));
		const bobFile = path.join(directory, 'bob.sqlite');
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const arm = { down: false };
		const hooks = (): Partial<IAuxiliaryChannelConfig> => ({
			prepareForward: (request): IAuxiliaryForwardTerms => {
				asked.push(request);
				return valued(request);
			},
			onForwardLegResolved: (resolution): void => {
				told.push(resolution);
			},
			...bobExtra(arm)
		});
		const alice = assetHost(tag, 1, {});
		const bob = assetHost(tag, 2, hooks(), { sqlitePath: bobFile });
		const carol = plainHost(tag, 3);
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		const context = {} as IContext;
		context.assetChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		context.outChannel = openReadyChannel(bob.node, carol.node);
		context.alice = alice.node.getNodeId();
		context.carol = carol.node.getNodeId();
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
						shortChannelId: ORDINARY_SCID,
						amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
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
					channelId: context.assetChannel,
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

	/** Bob's provider cannot build a commitment while `arm.down`. */
	const refuser = (arm: {
		down: boolean;
	}): Partial<IAuxiliaryChannelConfig> => ({
		provider: failingProvider(
			(method) => method === 'buildCommitment' && arm.down
		)
	});

	/** The refusals of its asset provider a host reported. */
	const refusals = (host: IAssetHost, operation: string): string[] =>
		host.errors.filter((error) =>
			error.includes(`The asset provider refused ${operation}`)
		);

	/** The decision Bob's stored row of the asset channel holds for HTLC 0. */
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

	it('asks once: a reestablish and a restart with the forward in flight ask nothing again, and the payment still settles', async () => {
		const tag = 'aux-fwd-in-restart';
		const s = await scene(tag, () => ({}));
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
		const state = restarted.node
			.getChannelManager()
			.getChannel(s.context.assetChannel)!
			.getFullState();
		expect([
			state.auxiliaryState!.localBalance,
			state.auxiliaryState!.remoteBalance
		]).to.deep.equal([1000n + INCOMING_UNITS, 9000n - INCOMING_UNITS]);
		expect(legEnds(s.told)).to.deep.equal([
			'incoming:fulfilled',
			'outgoing:fulfilled'
		]);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('writes its decision to settle with the asset channel as soon as the preimage comes back, keeps the link while the payer is away, and settles once the payer is back', async () => {
		const tag = 'aux-fwd-in-away';
		const s = await scene(tag, () => ({}));
		// Alice goes away: the asset channel waits for its reestablish.
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
		const decision = storedDecision(s.bob, s.context.assetChannel);
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
		expect(legEnds(s.told)).to.deep.equal([
			'incoming:fulfilled',
			'outgoing:fulfilled'
		]);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('keeps the link while its provider refuses the settlement upstream, and lets it go with the settlement the channel takes', async () => {
		const tag = 'aux-fwd-in-provider-refuses';
		const s = await scene(tag, refuser);
		s.arm.down = true;
		expect(s.carol.node.settleHeldHtlc(s.paymentHash, s.preimage)).to.equal(
			true
		);
		await settle();
		await settle();
		// Carol is paid; Alice is not settled yet, and Bob keeps what lets him
		// settle her: the link, and the decision with the asset channel.
		expect(refusals(s.bob, 'the settlement of an HTLC')).to.have.length(1);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(storedDecision(s.bob, s.context.assetChannel)?.outcome).to.equal(
			'settle'
		);

		s.arm.down = false;
		s.bob.node.handleNewBlock(1);
		await turns(200);
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		// One HTLC went out to Carol, and the host was asked once.
		expect(
			s.bob.node
				.getChannelManager()
				.getChannel(s.context.outChannel)!
				.getFullState().localHtlcCounter
		).to.equal(1n);
		expect(s.asked).to.have.length(1);
		expect(legEnds(s.told)).to.deep.equal([
			'incoming:fulfilled',
			'outgoing:fulfilled'
		]);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('forwards nothing a second time when it stops while its provider refuses the settlement upstream, and settles the payer from what it kept', async () => {
		const tag = 'aux-fwd-in-provider-restart';
		const s = await scene(tag, refuser);
		s.arm.down = true;
		expect(s.carol.node.settleHeldHtlc(s.paymentHash, s.preimage)).to.equal(
			true
		);
		await settle();
		await settle();
		expect(refusals(s.bob, 'the settlement of an HTLC')).to.have.length(1);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);

		// Bob stops and starts again with a provider that answers.
		s.arm.down = false;
		const restarted = restart(s, tag);
		await reconnectHosts(s.alice, restarted);
		await reconnectHosts(restarted, s.carol);
		await settle();
		restarted.node.handleNewBlock(1);
		await turns(200);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(restarted.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		// Still the one HTLC to Carol, and the one ask.
		expect(
			restarted.node
				.getChannelManager()
				.getChannel(s.context.outChannel)!
				.getFullState().localHtlcCounter
		).to.equal(1n);
		expect(s.asked).to.have.length(1);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('writes its decision and keeps the link when a preimage learned on the chain meets a provider that refuses the settlement upstream', async () => {
		const tag = 'aux-fwd-in-chain-preimage';
		const s = await scene(tag, refuser);
		s.arm.down = true;
		(
			s.bob.node as unknown as {
				handleOnChainPreimageLearned: (
					paymentHash: Buffer,
					preimage: Buffer
				) => void;
			}
		).handleOnChainPreimageLearned(s.paymentHash, s.preimage);
		await settle();
		expect(refusals(s.bob, 'the settlement of an HTLC')).to.have.length(1);
		expect(storedDecision(s.bob, s.context.assetChannel)?.outcome).to.equal(
			'settle'
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
			PaymentStatus.COMPLETED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('fails the payer back through the forward when its outgoing leg timed out on the chain, keeping the link while its provider refuses the failure', async () => {
		const tag = 'aux-fwd-in-chain-timeout';
		const s = await scene(tag, refuser);
		const resolved = s.bob.node as unknown as {
			handleOnChainOutputResolved: (
				channelId: Buffer | undefined,
				outputType: OutputType,
				paymentHash?: Buffer,
				htlcId?: bigint
			) => void;
		};
		// The outgoing HTLC's output resolved on the chain with no preimage.
		s.arm.down = true;
		resolved.handleOnChainOutputResolved(
			s.context.outChannel,
			OutputType.OFFERED_HTLC,
			s.paymentHash,
			0n
		);
		await settle();
		expect(refusals(s.bob, 'the failure of an HTLC')).to.have.length(1);
		expect(storedDecision(s.bob, s.context.assetChannel)?.outcome).to.equal(
			'fail'
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(1);
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// Driven again with a provider that answers: the failure goes up, and
		// the link goes with it.
		s.arm.down = false;
		resolved.handleOnChainOutputResolved(
			s.context.outChannel,
			OutputType.OFFERED_HTLC,
			s.paymentHash,
			0n
		);
		await settle();
		await settle();
		expect(s.alice.node.getPayment(s.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.storage!.loadAllForwardedHtlcs()).to.have.length(0);
		expect(s.asked).to.have.length(1);
		// The outgoing leg ends on the chain, which this test drives only as
		// far as the event that fails the incoming leg back.
		expect(legEnds(s.told)).to.deep.equal(['incoming:failed']);
		fs.rmSync(s.directory, { recursive: true, force: true });
	});

	it('does not ask again after a restart about an HTLC it refused after the ask, when its provider refused the failure', async () => {
		const tag = 'aux-fwd-in-refused-restart';
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), `${tag}-`));
		const bobFile = path.join(directory, 'bob.sqlite');
		fixRandomness(tag);
		const asked: IAuxiliaryForwardRequest[] = [];
		const told: IAuxiliaryForwardLegResolution[] = [];
		const arm = { down: false };
		const hooks = (): Partial<IAuxiliaryChannelConfig> => ({
			prepareForward: (request): IAuxiliaryForwardTerms => {
				asked.push(request);
				// The value does not cover the amount and the fee. The node
				// refuses, and the provider then refuses the failure.
				arm.down = true;
				return { incomingValueMsat: FORWARD_MSAT };
			},
			onForwardLegResolved: (resolution): void => {
				told.push(resolution);
			},
			...refuser(arm)
		});
		const alice = assetHost(tag, 1, {});
		const bob = assetHost(tag, 2, hooks(), { sqlitePath: bobFile });
		const carol = plainHost(tag, 3);
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);
		const assetChannel = await openAssetChannel(alice, bob, {
			tag: `${tag} in`,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const outChannel = openReadyChannel(bob.node, carol.node);
		await settle();
		const outAlias = bob.node
			.getChannelManager()
			.getChannel(outChannel)!
			.getFullState().scidAlias!;
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
						amountToForwardMsat: INCOMING_UNITS * MSAT_PER_UNIT,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
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
					channelId: assetChannel,
					wireAmountMsat: CARRIER_MSAT,
					customRecords: amountRecord(INCOMING_UNITS)
				}
			}
		);
		await settle();
		await settle();
		expect(asked).to.have.length(1);
		expect(told).to.have.length(1);
		expect(refusals(bob, 'the failure of an HTLC')).to.have.length(1);
		expect(
			bob
				.storage!.loadChannel(assetChannel.toString('hex'))
				?.state.auxiliaryState?.htlcDecisions?.get('0')?.outcome
		).to.equal('fail');
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// Bob stops and starts again with a provider that answers.
		bob.node.destroy();
		bob.storage!.close();
		arm.down = false;
		const restartedHooks = hooks();
		const restarted = assetHost(
			tag,
			2,
			{
				...restartedHooks,
				prepareForward: (request): IAuxiliaryForwardTerms => {
					asked.push(request);
					return valued(request);
				}
			},
			{ sqlitePath: bobFile }
		);
		hosts.push(restarted);
		connectHosts(alice, restarted);
		connectHosts(restarted, carol);
		await reconnectHosts(alice, restarted);
		await settle();
		restarted.node.handleNewBlock(1);
		await turns(200);
		expect(alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(asked).to.have.length(1);
		expect(told.map((end) => `${end.leg}:${end.outcome}`).sort()).to.deep.equal(
			['incoming:failed', 'outgoing:never-offered']
		);
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('takes back a decision, or the mark that it asks, whose row the storage did not commit', async () => {
		const tag = 'aux-fwd-in-not-committed';
		const s = await scene(tag, () => ({}));
		const manager = s.bob.node.getChannelManager();
		const channel = manager.getChannel(s.context.assetChannel)!;
		const persistence = (
			manager as unknown as {
				persistence: { persist: (...args: unknown[]) => unknown };
			}
		).persistence;
		const persist = persistence.persist;
		persistence.persist = (): unknown => ({
			committed: false,
			outboxIds: []
		});
		try {
			expect(
				manager.recordForwardDecision(
					s.context.assetChannel,
					0n,
					'settle',
					s.preimage
				)
			).to.equal(false);
			expect(channel.auxiliaryHtlcDecision(0n)).to.equal(undefined);
			channel.unmarkForwardAsked(0n);
			expect(manager.recordForwardAsk(s.context.assetChannel, 0n)).to.equal(
				false
			);
			expect(channel.forwardAsked(0n)).to.equal(false);
		} finally {
			persistence.persist = persist;
		}
		expect(manager.recordForwardAsk(s.context.assetChannel, 0n)).to.equal(true);
		expect(
			manager.recordForwardDecision(
				s.context.assetChannel,
				0n,
				'settle',
				s.preimage
			)
		).to.equal(true);
		expect(channel.auxiliaryHtlcDecision(0n)?.outcome).to.equal('settle');
		fs.rmSync(s.directory, { recursive: true, force: true });
	});
});
