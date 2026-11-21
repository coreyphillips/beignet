/**
 * An asset payment sent in parts (issue #2098, step 9), on the chain world
 * of auxiliary-forward-world.ts: Alice is a wallet that pays through Bob,
 * her primary, over one or two asset channels with him. Bob's host values
 * each asset HTLC she sends and forwards it to Carol as a forward of its
 * own, over an ordinary channel (asset in, bitcoin out), and Carol collects
 * the parts as any multi-part set. What Alice's host is told and what her
 * node emits are kept on the scene, with arms a test pulls to make one part
 * fail: Bob's host refuses a forward, Alice's provider refuses an add, or
 * Carol's node times out a set it is collecting.
 *
 * A loopback pair is here too: two nodes whose messages pass in the same
 * call, so that a part's fulfil or failure runs inside its own add.
 */

import type { IChannelAuxiliaryProvider } from '../../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryForwardLegResolution,
	IAuxiliaryForwardRequest
} from '../../../src/lightning/channel/auxiliary-forward';
import type { IAuxiliaryChannelConfig } from '../../../src/lightning/channel/auxiliary-funding';
import {
	bobHooks,
	listenBob,
	type IScene,
	type Shape
} from './auxiliary-forward-scene';
import {
	FORWARD_CARRIER_MSAT,
	type IAssetPartSent,
	type IForwardWorld,
	type IForwardWorldOptions
} from './auxiliary-forward-world';
import {
	RECEIVE_IN_PARTS,
	SEND_IN_PARTS,
	assetHost,
	connectHosts,
	openAssetChannel,
	type IAssetHost
} from './auxiliary-nodes';
import { amountRecord } from './auxiliary-pair';

export type Log = {
	category: string;
	action: string;
	data: Record<string, unknown>;
};

/** One end of an asset HTLC that Alice's host was told of (onHtlcResolved). */
export interface IAliceEnd {
	outcome: string;
	direction: string;
	channelId: Buffer;
	htlcId: bigint;
	paymentHash: Buffer;
	units: bigint;
}

export interface ISendScene {
	w: IForwardWorld;
	shape: Shape;
	/** What Bob's host was asked about each forward, and told of each leg's end. */
	asked: IAuxiliaryForwardRequest[];
	told: IAuxiliaryForwardLegResolution[];
	/** Bob's structured logs and forward events. */
	logs: Log[];
	forwarded: Array<Record<string, unknown>>;
	refused: Array<Record<string, unknown>>;
	/** Each end Alice's host was told of, in order. */
	resolved: IAliceEnd[];
	/** Alice's structured logs. */
	aliceLogs: Log[];
	/** Alice's payment:sent and payment:failed, as payment hash hex, in order. */
	sent: string[];
	failed: string[];
	/** Bob's host refuses this many of the next forwards it is asked about. */
	bobRefuses: { next: number };
	/** Alice's provider refuses this many of the next asset HTLCs she adds, at the add. */
	aliceRefusesAdds: { next: number };
	/** Alice's hooks as she was opened with them, for a restart. */
	aliceHooks: Partial<IAuxiliaryChannelConfig>;
}

export interface ISendSceneOptions {
	/** Alice's host opts in with sendInParts: true, unless false. */
	optIn?: boolean;
	alice?: Partial<IAuxiliaryChannelConfig>;
	bob?: Partial<IAuxiliaryChannelConfig>;
	world?: Partial<IForwardWorldOptions>;
}

/** An end Alice's host was told of, copied. */
function endOf(
	context: Parameters<NonNullable<IAuxiliaryChannelConfig['onHtlcResolved']>>[0]
): IAliceEnd {
	return {
		outcome: context.outcome,
		direction: String(context.direction),
		channelId: Buffer.from(context.channelId),
		htlcId: context.htlcId,
		paymentHash: Buffer.from(context.paymentHash),
		units: context.auxiliaryAmount
	};
}

/**
 * The provider, refusing the next `arm.next` asset HTLCs its node adds: it
 * throws in validateHtlc, which the channel asks at the add, after the node
 * has recorded the payment.
 */
export function refusingAdds(arm: {
	next: number;
}): (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider {
	return (provider) =>
		new Proxy(provider, {
			get(target, key, receiver): unknown {
				const value = Reflect.get(target, key, receiver) as unknown;
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					if (key === 'validateHtlc' && arm.next > 0) {
						arm.next--;
						throw new Error('the provider refuses this HTLC at its add');
					}
					return (value as (...rest: unknown[]) => unknown).apply(target, args);
				};
			}
		});
}

/** Alice's events and logs, kept on the scene; again after a restart. */
export function listenAlice(s: ISendScene): void {
	const alice = s.w.hosts.alice.node;
	alice.on('log', (log: Log) => {
		s.aliceLogs.push(log);
	});
	alice.on('payment:sent', (payment: { paymentHash: Buffer }) => {
		s.sent.push(payment.paymentHash.toString('hex'));
	});
	alice.on('payment:failed', (payment: { paymentHash: Buffer }) => {
		s.failed.push(payment.paymentHash.toString('hex'));
	});
}

/**
 * Open the world for asset in, bitcoin out, with Alice's host opted in to
 * sending in parts unless said, and fee coins for every host.
 */
export async function openSendScene(
	world: {
		open(tag: string, options: IForwardWorldOptions): Promise<IForwardWorld>;
		mine(world: IForwardWorld, blocks: number): Promise<void>;
	},
	tag: string,
	options: ISendSceneOptions = {}
): Promise<ISendScene> {
	const s = {
		shape: ['asset', 'ordinary'],
		asked: [],
		told: [],
		logs: [],
		forwarded: [],
		refused: [],
		resolved: [],
		aliceLogs: [],
		sent: [],
		failed: [],
		bobRefuses: { next: 0 },
		aliceRefusesAdds: { next: 0 }
	} as unknown as ISendScene;
	s.aliceHooks = {
		...(options.optIn === false ? {} : SEND_IN_PARTS),
		onHtlcResolved: (context): void => {
			s.resolved.push(endOf(context));
		},
		...options.alice
	};
	const w = await world.open(tag, {
		kinds: { in: 'asset', out: 'ordinary' },
		feeWallet: { alice: true, bob: true, carol: true },
		...options.world,
		wrapProvider: {
			alice: refusingAdds(s.aliceRefusesAdds),
			...options.world?.wrapProvider
		},
		hooks: {
			alice: s.aliceHooks,
			bob: bobHooks(s, {
				answer: (_request, terms) => {
					if (s.bobRefuses.next > 0) {
						s.bobRefuses.next--;
						throw new Error("Bob's host refuses this forward");
					}
					return terms;
				},
				...(options.bob ? { bob: options.bob } : {})
			})
		}
	});
	s.w = w;
	for (const name of ['alice', 'bob', 'carol'] as const) {
		for (let i = 0; i < 2; i++) w.wallets[name]!.fund(100_000);
	}
	await world.mine(w, 1);
	listenBob(s as unknown as IScene);
	listenAlice(s);
	return s;
}

/**
 * Carol's node fails back every part of each set it is still collecting,
 * as its timer does once a set is older than mppTimeoutMs.
 */
export function timeOutSets(host: IAssetHost): void {
	const timer = host.node as unknown as {
		mppTimeoutMs: number;
		failTimedOutMppPayments: () => void;
	};
	const prior = timer.mppTimeoutMs;
	timer.mppTimeoutMs = -1;
	try {
		timer.failTimedOutMppPayments();
	} finally {
		timer.mppTimeoutMs = prior;
	}
}

/**
 * Alice's node stops at its next add of an HTLC: a copy of her database is
 * taken at `snapshot` as it is then (the part recorded, its HTLC not in the
 * channel), and the add throws. Restored from the copy, she is the node that
 * stopped there.
 */
export function stopAtAdd(s: ISendScene, snapshot: string): { stops: number } {
	const stop = { stops: 0 };
	const alice = s.w.hosts.alice;
	const manager = alice.node.getChannelManager() as unknown as {
		addHtlc: (...args: unknown[]) => unknown;
	};
	manager.addHtlc = (): unknown => {
		delete (manager as { addHtlc?: unknown }).addHtlc;
		(
			alice.storage as unknown as { db: { exec(sql: string): unknown } }
		).db.exec(`VACUUM INTO '${snapshot}'`);
		stop.stops++;
		throw new Error('the node stopped here');
	};
	return stop;
}

/** Two loopback nodes with an asset channel, Alice paying Bob in parts. */
export interface IPartsPair {
	alice: IAssetHost;
	bob: IAssetHost;
	channelId: Buffer;
	resolved: IAliceEnd[];
	sent: string[];
	failed: string[];
	/** Bob's host refuses this many of the next asset HTLCs it is asked to value. */
	bobRefuses: { next: number };
}

/**
 * Alice (opted in to sending in parts) and Bob (opted in to receiving in
 * parts, a unit worth 1000 msat) on loopback nodes, whose messages pass in
 * the same call: a part that completes Bob's set is fulfilled, and a part
 * Bob refuses is failed, inside Alice's add of it. The hosts are pushed on
 * `hosts` for the test to destroy.
 */
export async function partsPair(
	tag: string,
	hosts: IAssetHost[]
): Promise<IPartsPair> {
	const pair = {
		resolved: [],
		sent: [],
		failed: [],
		bobRefuses: { next: 0 }
	} as unknown as IPartsPair;
	pair.alice = assetHost(
		tag,
		1,
		{
			...SEND_IN_PARTS,
			onHtlcResolved: (context): void => {
				pair.resolved.push(endOf(context));
			}
		},
		{ sqlite: true }
	);
	pair.bob = assetHost(
		tag,
		2,
		{
			...RECEIVE_IN_PARTS,
			valueIncomingHtlc: (context): bigint | undefined => {
				if (context.auxiliaryAmount === undefined) return undefined;
				if (pair.bobRefuses.next > 0) {
					pair.bobRefuses.next--;
					throw new Error("Bob's host refuses this part");
				}
				return context.auxiliaryAmount * 1000n;
			}
		},
		{ sqlite: true }
	);
	hosts.push(pair.alice, pair.bob);
	connectHosts(pair.alice, pair.bob);
	pair.channelId = await openAssetChannel(pair.alice, pair.bob, {
		tag,
		openerUnits: 9000n,
		acceptorUnits: 1000n
	});
	pair.alice.node.on('payment:sent', (payment: { paymentHash: Buffer }) => {
		pair.sent.push(payment.paymentHash.toString('hex'));
	});
	pair.alice.node.on('payment:failed', (payment: { paymentHash: Buffer }) => {
		pair.failed.push(payment.paymentHash.toString('hex'));
	});
	return pair;
}

/**
 * Alice sends Bob one part of `invoice` over the pair's channel: one hop,
 * its value in units at 1000 msat a unit, declaring the invoice's total.
 */
export function sendPairPart(
	pair: IPartsPair,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer; totalMsat: bigint },
	valueMsat: bigint,
	totalMsat: bigint | undefined = invoice.totalMsat
): IAssetPartSent {
	const units = valueMsat / 1000n;
	const htlcId = pair.alice.node
		.getChannelManager()
		.getChannel(pair.channelId)!
		.getFullState().localHtlcCounter;
	const sent: IAssetPartSent = {
		channelId: pair.channelId,
		htlcId,
		units,
		routeAmountMsat: valueMsat,
		valueMsat,
		wireAmountMsat: FORWARD_CARRIER_MSAT
	};
	try {
		sent.payment = pair.alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(pair.bob.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: valueMsat,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			totalMsat,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId: pair.channelId,
					wireAmountMsat: FORWARD_CARRIER_MSAT,
					customRecords: amountRecord(units)
				}
			}
		);
	} catch (error) {
		sent.error = error;
	}
	return sent;
}
