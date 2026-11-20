/**
 * Issue #2098, step 1: the contract of a forward with an asset leg, and
 * step 5: the build that runs it.
 *
 * The types a host writes its forward hooks against are exported from the
 * lightning entry, and AUXILIARY_CHANNELS_API names the part among its
 * surfaces from step 5 on, with nothing left declared. With the switch for
 * asset forwards off, a node in the middle whose host supplies the hooks
 * refuses every forward with an asset leg exactly as one whose host does
 * not: the same messages on the wire, byte for byte, in each of the three
 * directions and for a next hop that is a short channel id the node has no
 * channel for. Neither hook is called.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { channel as lightningChannel } from '../../src/lightning';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryPayment
} from '../../src/lightning/channel/auxiliary-funding';
import { HtlcDirection } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	TEMPORARY_CHANNEL_FAILURE,
	UNKNOWN_NEXT_PEER
} from '../../src/lightning/onion/types';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	fixRandomness,
	openAssetChannel,
	restoreRandomness,
	withAssetForwards,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

type Hooks = Partial<IAuxiliaryChannelConfig>;

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** The scid openReadyChannel gives the ordinary channel of a pair. */
const ORDINARY_SCID = Buffer.from('0001f40000010000', 'hex');

/**
 * A short channel id no channel of the middle node has: what the hint of an
 * asset invoice names when it was made from a quote of that node's host.
 */
const QUOTE_SCID = hash('a quote of the middle node').subarray(0, 8);

/** How the payer reaches the middle node, and where the onion sends it on. */
interface IDirection {
	name: string;
	/** Alice and Bob share an asset channel, and Alice pays in units. */
	assetIn: boolean;
	/** Bob and Carol share an asset channel, and not an ordinary one. */
	assetOut: boolean;
	/** The onion names a short channel id Bob has no channel for. */
	quote: boolean;
}

const DIRECTIONS: IDirection[] = [
	{
		name: 'bitcoin in, to a short channel id the node has no channel for',
		assetIn: false,
		assetOut: true,
		quote: true
	},
	{
		name: 'bitcoin in, asset out over the asset channel the onion names',
		assetIn: false,
		assetOut: true,
		quote: false
	},
	{
		name: 'asset in, bitcoin out',
		assetIn: true,
		assetOut: false,
		quote: false
	},
	{
		name: 'asset in, asset out',
		assetIn: true,
		assetOut: true,
		quote: false
	},
	{
		name: 'asset in, to a short channel id the node has no channel for',
		assetIn: true,
		assetOut: true,
		quote: true
	}
];

interface IRun {
	/** The hash of every message the three nodes sent, in order. */
	transcript: string;
	/** How many messages that was. */
	messages: number;
	/** The hooks of Bob's host that were called, in order. */
	asked: string[];
	alice: PaymentStatus | undefined;
	/** The failure Alice read, and the hop it came from. */
	failure: [number | undefined, number | undefined];
	carol: PaymentStatus | undefined;
	/** HTLCs Bob offered on his channel to Carol. */
	offered: bigint;
	/** Rows of Bob's forwarding history. */
	forwards: number;
	/** Bob's persisted links of an outgoing HTLC to the incoming one. */
	links: number;
}

describe('a forward with an asset leg, under the declared contract (issue #2098, step 1)', function () {
	this.timeout(120_000);
	withAssetOpens();
	// What the build did before step 5 turned the switch on, and does with
	// it off.
	withAssetForwards(false);
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		restoreRandomness();
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	it('is typed from the lightning entry, and a host can supply both hooks', () => {
		const channelId = hash('forward contract channel');
		const request: lightningChannel.IAuxiliaryForwardRequest = {
			paymentHash: hash('forward contract payment'),
			incoming: {
				channelId,
				peerPubkey: '02'.padEnd(66, '1'),
				htlcId: 0n,
				wireAmountMsat: 354_000n,
				cltvExpiry: 940,
				auxiliaryAmount: 5010n,
				customRecords: amountRecord(5010n),
				auxiliaryChannel: true
			},
			shortChannelId: QUOTE_SCID,
			amountToForwardMsat: 5_000_000n,
			outgoingCltvExpiry: 900
		};
		const terms: lightningChannel.IAuxiliaryForwardTerms = {
			outgoingChannel: {
				channelId: hash('forward contract outgoing channel'),
				peerPubkey: '03'.padEnd(66, '2')
			},
			incomingValueMsat: 5_010_000n,
			outgoingHtlc: {
				customRecords: amountRecord(5000n),
				wireAmountMsat: 354_000n
			}
		};
		const ended: lightningChannel.IAuxiliaryForwardLegResolution[] = [];
		const hooks: Pick<
			lightningChannel.IAuxiliaryChannelConfig,
			'prepareForward' | 'onForwardLegResolved'
		> = {
			prepareForward: (asked) =>
				asked.outgoing === undefined ? terms : undefined,
			onForwardLegResolved: (resolution) => {
				ended.push(resolution);
			}
		};
		expect(hooks.prepareForward!(request)).to.equal(terms);
		const resolution: lightningChannel.IAuxiliaryForwardLegResolution = {
			paymentHash: request.paymentHash,
			incomingChannelId: channelId,
			incomingHtlcId: 0n,
			leg: 'outgoing',
			channelId: terms.outgoingChannel!.channelId,
			outcome: 'never-offered',
			onChain: false,
			customRecords: new Map()
		};
		hooks.onForwardLegResolved!(resolution);
		expect(ended).to.deep.equal([resolution]);
	});

	it('is named among the surfaces of AUXILIARY_CHANNELS_API from the build that runs it, with nothing left declared (step 5)', () => {
		const api = lightningChannel.AUXILIARY_CHANNELS_API;
		expect(api.version).to.equal(1);
		expect([...api.declared]).to.deep.equal([]);
		expect(Object.isFrozen(api.declared)).to.equal(true);
		const surface: lightningChannel.AuxiliaryChannelsSurface = 'prepareForward';
		expect((api.surfaces as readonly string[]).includes(surface)).to.equal(
			true
		);
	});

	/**
	 * Alice pays Carol's invoice through Bob, in `direction`. Bob runs on
	 * SQLite, and his host supplies the forward hooks when `withHooks` says
	 * so, with answers that would take every forward on.
	 */
	async function run(direction: IDirection, withHooks: boolean): Promise<IRun> {
		const tag = `aux-forward-contract-${DIRECTIONS.indexOf(direction)}`;
		fixRandomness(tag);
		const asked: string[] = [];
		let outgoingAssetChannel: Buffer | undefined;
		const forwardHooks: Hooks = {
			prepareForward: (request) => {
				asked.push('prepareForward');
				const assetLegIn =
					request.incoming.auxiliaryChannel ||
					request.incoming.auxiliaryAmount !== undefined;
				return {
					...(request.outgoing === undefined
						? {
								outgoingChannel: {
									channelId: outgoingAssetChannel!,
									peerPubkey: carol.node.getNodeId()
								}
						  }
						: {}),
					...(assetLegIn
						? { incomingValueMsat: request.amountToForwardMsat + 10_000n }
						: {}),
					...(direction.assetOut
						? {
								outgoingHtlc: {
									customRecords: amountRecord(5000n),
									wireAmountMsat: 354_000n
								}
						  }
						: {})
				};
			},
			onForwardLegResolved: () => {
				asked.push('onForwardLegResolved');
			}
		};
		const bobHooks: Hooks = {
			valueIncomingHtlc: (context) => {
				asked.push('valueIncomingHtlc');
				return context.auxiliaryAmount === undefined
					? undefined
					: context.auxiliaryAmount * 1000n;
			},
			onHtlcResolved: (context) => {
				asked.push(`onHtlcResolved:${context.direction}:${context.outcome}`);
			},
			...(withHooks ? forwardHooks : {})
		};
		const unitsAreWorth: Hooks = {
			valueIncomingHtlc: (context) =>
				context.auxiliaryAmount === undefined
					? undefined
					: context.auxiliaryAmount * 1000n
		};
		const alice = assetHost(tag, 1, unitsAreWorth);
		const bob = assetHost(tag, 2, bobHooks, { sqlite: true });
		const carol = assetHost(tag, 3, unitsAreWorth);
		hosts.push(alice, bob, carol);
		connectHosts(alice, bob);
		connectHosts(bob, carol);

		let assetPayment: IAuxiliaryPayment | undefined;
		if (direction.assetIn) {
			const channelId = await openAssetChannel(alice, bob, {
				tag: `${tag} in`,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			assetPayment = {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: amountRecord(5010n)
			};
		} else {
			openReadyChannel(alice.node, bob.node);
		}
		let next: Buffer;
		let outChannelId: Buffer;
		if (direction.assetOut) {
			outChannelId = await openAssetChannel(bob, carol, {
				tag: `${tag} out`,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			outgoingAssetChannel = outChannelId;
			next = bob.node.getAuxiliaryChannelInfo(outChannelId)!.shortChannelId!;
		} else {
			outChannelId = openReadyChannel(bob.node, carol.node);
			const state = bob.node
				.getChannelManager()
				.getChannel(outChannelId)!
				.getFullState();
			next = (state.shortChannelId ?? state.scidAlias)!;
		}
		if (direction.quote) next = QUOTE_SCID;
		await settle();

		const wire: string[] = [];
		for (const [from, host] of [
			['alice', alice],
			['bob', bob],
			['carol', carol]
		] as const) {
			host.node.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					wire.push(`${from}:${type}:${payload.toString('hex')}`);
				}
			);
		}
		const invoice = carol.node.createInvoice({
			amountMsat: 5_000_000n,
			description: direction.name
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: ORDINARY_SCID,
						amountToForwardMsat: 5_010_000n,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
						shortChannelId: next,
						amountToForwardMsat: 5_000_000n,
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
			assetPayment ? { assetPayment } : undefined
		);
		await settle();

		return {
			transcript: crypto
				.createHash('sha256')
				.update(wire.join('\n'))
				.digest('hex'),
			messages: wire.length,
			asked,
			alice: alice.node.getPayment(invoice.paymentHash)?.status,
			failure: [
				alice.node.getPayment(invoice.paymentHash)?.failureCode,
				alice.node.getPayment(invoice.paymentHash)?.failureSourceIndex
			],
			carol: carol.node.getPayment(invoice.paymentHash)?.status,
			offered: bob.node
				.getChannelManager()
				.getChannel(outChannelId)!
				.getFullState().localHtlcCounter,
			forwards: bob.storage!.listForwardingEvents().length,
			links: bob.storage!.loadAllForwardedHtlcs().length
		};
	}

	for (const direction of DIRECTIONS) {
		it(`${direction.name}: refused as by a host without the hooks, byte for byte, and neither hook is called`, async () => {
			const without = await run(direction, false);
			for (const host of hosts.splice(0)) {
				host.node.destroy();
				host.storage?.close();
			}
			restoreRandomness();
			const withHooks = await run(direction, true);

			// Refused as it always was: Alice's payment failed back from Bob,
			// with unknown_next_peer for a short channel id he has no channel
			// for and temporary_channel_failure otherwise. Carol was not paid,
			// Bob offered nothing onward and recorded no forward.
			for (const result of [without, withHooks]) {
				expect(result.alice).to.equal(PaymentStatus.FAILED);
				expect(result.failure).to.deep.equal([
					direction.quote && !direction.assetIn
						? UNKNOWN_NEXT_PEER
						: TEMPORARY_CHANNEL_FAILURE,
					0
				]);
				expect(result.carol).to.not.equal(PaymentStatus.COMPLETED);
				expect(result.offered).to.equal(0n);
				expect(result.forwards).to.equal(0);
				expect(result.links).to.equal(0);
			}
			// The same messages, and the same hooks of Bob's host: neither
			// forward hook is among them.
			expect(withHooks.messages).to.be.above(0);
			expect(withHooks.messages).to.equal(without.messages);
			expect(withHooks.transcript).to.equal(without.transcript);
			expect(withHooks.asked).to.deep.equal(without.asked);
			expect(withHooks.asked).to.not.include('prepareForward');
			expect(withHooks.asked).to.not.include('onForwardLegResolved');
			// An HTLC that came in with units is failed back on its channel,
			// and the host hears of it as before; valueIncomingHtlc is never
			// asked about a forward.
			expect(withHooks.asked).to.deep.equal(
				direction.assetIn
					? [`onHtlcResolved:${HtlcDirection.RECEIVED}:failed`]
					: []
			);
		});
	}
});
