/**
 * A forward with an asset leg in flight on the three-node world of
 * auxiliary-forward-world.ts (issue #2098): Alice pays Carol's hold invoice
 * through Bob, whose host takes the forward on, and Carol holds the HTLC
 * until a test settles or cancels it. Bob's channel with Alice is the
 * incoming side and his channel with Carol the outgoing side; either is an
 * asset channel or an ordinary one. What Bob's host is asked and told, and
 * what Bob logs and emits about forwards, is kept on the scene.
 */

import type {
	IAuxiliaryForwardLegResolution,
	IAuxiliaryForwardRequest,
	IAuxiliaryForwardTerms
} from '../../../src/lightning/channel/auxiliary-forward';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryIncomingHtlc
} from '../../../src/lightning/channel/auxiliary-funding';
import { RECEIVE_IN_PARTS } from './auxiliary-nodes';
import {
	FORWARD_CARRIER_MSAT,
	forwardHeld,
	type ForwardChannelKind,
	type IForwardPayment,
	type IForwardWorld,
	type IForwardWorldOptions
} from './auxiliary-forward-world';
import { settle } from './auxiliary-on-chain';
import { amountRecord, hash } from './auxiliary-pair';

/** What Alice sends Bob over an asset channel, and what Bob's host values each unit at. */
export const INCOMING_UNITS = 5010n;
export const MSAT_PER_UNIT = 1000n;
/** What Alice sends Bob over an ordinary channel. */
export const INCOMING_MSAT = 5_100_000n;
/** The units Bob's host makes an outgoing asset HTLC carry, and what the onion asks Bob to forward. */
export const OUTGOING_UNITS = 5000n;
export const FORWARD_MSAT = 5_000_000n;
/** The delta of the quotes' hints, and the node's default policy. */
export const CLTV_DELTA = 40;
/** How many blocks above the tip Bob's outgoing HTLC expires. */
export const OUTGOING_DELTA = 60;
/** A short channel id no channel of Bob's has: one a quote of his host's gave a hint. */
export const QUOTE_SCID = hash('a quote of the middle node, step 7').subarray(
	0,
	8
);

export type Shape = [ForwardChannelKind, ForwardChannelKind];
export const SHAPES: Shape[] = [
	['ordinary', 'asset'],
	['asset', 'ordinary'],
	['asset', 'asset']
];
export const shapeName = ([inKind, outKind]: Shape): string =>
	inKind === 'ordinary'
		? 'bitcoin in, asset out'
		: outKind === 'ordinary'
		? 'asset in, bitcoin out'
		: 'asset in, asset out';

/** What the incoming leg is worth to Bob's host: its units at the rate, or the bitcoin it carries. */
export const incomingWorth = ([inKind]: Shape): bigint =>
	inKind === 'asset' ? INCOMING_UNITS * MSAT_PER_UNIT : INCOMING_MSAT;

export interface IScene {
	w: IForwardWorld;
	shape: Shape;
	held: IForwardPayment;
	/** The next hop the onion names. */
	next: Buffer;
	asked: IAuxiliaryForwardRequest[];
	told: IAuxiliaryForwardLegResolution[];
	/** Bob's structured logs. */
	logs: Array<{
		category: string;
		action: string;
		data: Record<string, unknown>;
	}>;
	/** Bob's htlc:forwarded events. */
	forwarded: Array<Record<string, unknown>>;
	/** Bob's htlc:forward-refused events. */
	refused: Array<Record<string, unknown>>;
}

export interface ISceneOptions {
	/** The onion names a short channel id Bob's host claims for a quote (an outgoing asset leg only). */
	quote?: boolean;
	/** Bob's answer, given the terms a host would make that values each unit at the rate. */
	answer?: (
		request: IAuxiliaryForwardRequest,
		terms: IAuxiliaryForwardTerms
	) => IAuxiliaryForwardTerms | undefined;
	/** Bob's host is told how each leg ends (onForwardLegResolved), unless false. */
	ends?: boolean;
	/** Takes each end Bob's host is told; throwing leaves it untaken. */
	onEnd?: (end: IAuxiliaryForwardLegResolution) => void;
	/** Bob's other hooks. */
	bob?: Partial<IAuxiliaryChannelConfig>;
	world?: Partial<IForwardWorldOptions>;
	/** Runs once the channels are open, before Alice pays. */
	beforeSend?: (scene: IScene) => void;
	/** Carol must hold the HTLC; false when it is not to reach her. */
	held?: boolean;
}

/** Bob's events and logs, kept on the scene; again after a restart. */
export function listenBob(s: IScene): void {
	const bob = s.w.hosts.bob.node;
	bob.on(
		'log',
		(log: {
			category: string;
			action: string;
			data: Record<string, unknown>;
		}) => {
			s.logs.push(log);
		}
	);
	bob.on('htlc:forwarded', (event: Record<string, unknown>) => {
		s.forwarded.push(event);
	});
	bob.on('htlc:forward-refused', (event: Record<string, unknown>) => {
		s.refused.push(event);
	});
}

/** Bob's hooks of a scene, also for a restart. */
export function bobHooks(
	s: Pick<IScene, 'asked' | 'told' | 'shape'> & { w?: IForwardWorld },
	options: ISceneOptions
): Partial<IAuxiliaryChannelConfig> {
	const [inKind, outKind] = s.shape;
	return {
		prepareForward: (request): IAuxiliaryForwardTerms | undefined => {
			s.asked.push(request);
			const terms: IAuxiliaryForwardTerms = {
				...(options.quote && s.w
					? {
							outgoingChannel: {
								channelId: Buffer.from(s.w.outChannel),
								peerPubkey: s.w.hosts.carol.node.getNodeId()
							}
					  }
					: {}),
				...(inKind === 'asset'
					? {
							incomingValueMsat:
								request.incoming.auxiliaryAmount! * MSAT_PER_UNIT
					  }
					: {}),
				...(outKind === 'asset'
					? {
							outgoingHtlc: {
								customRecords: amountRecord(OUTGOING_UNITS),
								wireAmountMsat: FORWARD_CARRIER_MSAT
							}
					  }
					: {})
			};
			return options.answer ? options.answer(request, terms) : terms;
		},
		...(options.ends === false
			? {}
			: {
					onForwardLegResolved: (end): void => {
						options.onEnd?.(end);
						s.told.push(end);
					}
			  }),
		...options.bob
	};
}

/**
 * Open the world for `shape` and put Alice's payment in flight, held at
 * Carol. The onion names the outgoing channel by its alias, or a quote's
 * short channel id with `quote`.
 */
export async function openScene(
	world: {
		open(tag: string, options: IForwardWorldOptions): Promise<IForwardWorld>;
		mine(world: IForwardWorld, blocks: number): Promise<void>;
	},
	tag: string,
	shape: Shape,
	options: ISceneOptions = {}
): Promise<IScene> {
	const valued = (incoming: {
		auxiliaryAmount?: bigint;
	}): bigint | undefined =>
		incoming.auxiliaryAmount === undefined
			? undefined
			: incoming.auxiliaryAmount * MSAT_PER_UNIT;
	const s = {
		shape,
		asked: [],
		told: [],
		logs: [],
		forwarded: [],
		refused: []
	} as unknown as IScene;
	const w = await world.open(tag, {
		kinds: { in: shape[0], out: shape[1] },
		feeWallet: { alice: true, bob: true, carol: true },
		...options.world,
		hooks: {
			alice: { valueIncomingHtlc: valued },
			bob: bobHooks(s, options),
			carol: { valueIncomingHtlc: valued }
		}
	});
	s.w = w;
	for (const name of ['alice', 'bob', 'carol'] as const) {
		for (let i = 0; i < 2; i++) w.wallets[name]!.fund(100_000);
	}
	await world.mine(w, 1);
	listenBob(s);
	options.beforeSend?.(s);
	s.next = options.quote
		? Buffer.from(QUOTE_SCID)
		: Buffer.from(
				w.hosts.bob.node
					.getChannelManager()
					.getChannel(w.outChannel)!
					.getFullState().scidAlias!
		  );
	s.held = await forwardHeld(w, tag, {
		next: s.next,
		forwardMsat: FORWARD_MSAT,
		outgoingDelta: OUTGOING_DELTA,
		cltvDelta: CLTV_DELTA,
		units: INCOMING_UNITS,
		incomingMsat: INCOMING_MSAT,
		held: options.held
	});
	return s;
}

/** Message rounds until `reached`, or throw with what is missing. */
export async function rounds(
	what: string,
	reached: () => boolean,
	most = 30
): Promise<void> {
	for (let i = 0; i < most && !reached(); i++) await settle();
	if (!reached()) throw new Error(`never reached: ${what}`);
}

/** Carol settles the held HTLC, and the settle runs back to Alice. */
export async function settleAtCarol(s: IScene): Promise<void> {
	if (
		!s.w.hosts.carol.node.settleHeldHtlc(s.held.paymentHash, s.held.preimage)
	) {
		throw new Error('Carol holds nothing to settle');
	}
	await rounds(
		'the settle reaches Alice',
		() =>
			s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status ===
			'COMPLETED'
	);
}

/** Carol fails the held HTLC back, and the failure runs back to Alice. */
export async function cancelAtCarol(s: IScene): Promise<void> {
	if (!s.w.hosts.carol.node.cancelHoldInvoice(s.held.paymentHash)) {
		throw new Error('Carol holds nothing to cancel');
	}
	await rounds(
		'the failure reaches Alice',
		() =>
			s.w.hosts.alice.node.getPayment(s.held.paymentHash)?.status === 'FAILED'
	);
}

/** The ends Bob's host was told, as `leg:outcome`, sorted. */
export const legEnds = (s: IScene): string[] =>
	s.told.map((end) => `${end.leg}:${end.outcome}`).sort();

/*
 * An asset invoice paid in parts (issue #2098, step 8): Alice pays an
 * ordinary invoice of Carol's in bitcoin, one part at a time, and Bob's
 * host makes each part an asset HTLC to Carol, its units for what the onion
 * asks Bob to forward. Carol's host values each part against the parts it
 * already accepted.
 */

/** The custom record that names the quote a part's units were priced under. */
export const QUOTE_RECORD = 65538n;

/** A quote of Bob's host: its id, and what one unit is worth under it. */
export interface IPartQuote {
	id: number;
	msatPerUnit: bigint;
}
export const ONE_QUOTE: IPartQuote = { id: 1, msatPerUnit: MSAT_PER_UNIT };

/** The records of an asset part: its units and the quote they were priced under. */
export function partRecords(
	units: bigint,
	quote: IPartQuote = ONE_QUOTE
): Map<bigint, Buffer> {
	const records = amountRecord(units);
	records.set(QUOTE_RECORD, Buffer.from([quote.id]));
	return records;
}

/** The quote a part's records name, of `quotes`; the first when they name none. */
export function quoteOfRecords(
	records: ReadonlyMap<bigint, Buffer>,
	quotes: IPartQuote[] = [ONE_QUOTE]
): IPartQuote {
	const id = records.get(QUOTE_RECORD)?.[0];
	return quotes.find((quote) => quote.id === id) ?? quotes[0];
}

/**
 * Bob's answer for a part: the units for what the onion asks him to
 * forward, at the rate of the part's quote, rounded down as a host rounds.
 */
export function partsAnswer(
	quoteOf: (request: IAuxiliaryForwardRequest) => IPartQuote = () => ONE_QUOTE
): NonNullable<ISceneOptions['answer']> {
	return (request, terms) => {
		const quote = quoteOf(request);
		return {
			...terms,
			outgoingHtlc: {
				customRecords: partRecords(
					request.amountToForwardMsat / quote.msatPerUnit,
					quote
				),
				wireAmountMsat: FORWARD_CARRIER_MSAT
			}
		};
	};
}

/**
 * Carol's host valuing a part as a library's core does: the credits of the
 * parts it already accepted (acceptedHtlcs) are summed, this part is worth
 * its units at its quote's rate, and when the set then falls short of the
 * invoice by less than one unit per part, this part is topped up so that
 * the set reaches the invoice exactly. A plain HTLC is not the host's.
 */
export function setValuer(
	options: { topUp?: boolean; quotes?: IPartQuote[] } = {}
): (context: IAuxiliaryIncomingHtlc) => bigint | undefined {
	return (context) => {
		if (context.auxiliaryAmount === undefined) return undefined;
		const quote = quoteOfRecords(context.customRecords, options.quotes);
		const own = context.auxiliaryAmount * quote.msatPerUnit;
		if (options.topUp === false) return own;
		const invoiceMsat = context.invoice?.amountMsat ?? 0n;
		const before = context.acceptedHtlcs.reduce(
			(sum, part) => sum + part.amountMsat,
			0n
		);
		const short = invoiceMsat - before - own;
		const parts = BigInt(context.acceptedHtlcs.length + 1);
		return short > 0n && short < parts * quote.msatPerUnit ? own + short : own;
	};
}

export interface IPartsScene {
	w: IForwardWorld;
	shape: Shape;
	/** What Bob's host was asked about each forward, and told of each leg's end. */
	asked: IAuxiliaryForwardRequest[];
	told: IAuxiliaryForwardLegResolution[];
	/** Bob's structured logs and forward events. */
	logs: IScene['logs'];
	forwarded: IScene['forwarded'];
	refused: IScene['refused'];
	/** Each time Carol's host was asked to value an HTLC: what it was given. */
	carolAsks: IAuxiliaryIncomingHtlc[];
	/** Carol's structured logs, and her payment:received and invoice:settled events. */
	carolLogs: IScene['logs'];
	received: Array<{ paymentHash: Buffer }>;
	settled: Array<Record<string, unknown>>;
	/** Carol's hooks as she was opened with them, for a restart. */
	carolHooks: Partial<IAuxiliaryChannelConfig>;
}

export interface IPartsSceneOptions {
	/** Carol's host opts in with receiveInParts: true, unless false. */
	optIn?: boolean;
	/** Carol's host tops the part that completes a set up, unless false. */
	topUp?: boolean;
	quotes?: IPartQuote[];
	/** The quote Bob's host prices a part under; the first unless said. */
	quoteOf?: (request: IAuxiliaryForwardRequest) => IPartQuote;
	/** Runs each time Carol's host is asked, before it answers. */
	onCarolAsk?: (context: IAuxiliaryIncomingHtlc, s: IPartsScene) => void;
	carol?: Partial<IAuxiliaryChannelConfig>;
	bob?: Partial<IAuxiliaryChannelConfig>;
	world?: Partial<IForwardWorldOptions>;
	/** The fee coins each host's wallet is given; 2 unless said. */
	coins?: number;
	/** The fee coins Carol's wallet is given, in place of `coins`. */
	carolCoins?: number;
	/** The blocks mined once the wallets are funded; 1 unless said. */
	blocks?: number;
}

/** Carol's logs and events, kept on the scene; again after a restart. */
export function listenCarol(s: IPartsScene): void {
	const carol = s.w.hosts.carol.node;
	carol.on(
		'log',
		(log: {
			category: string;
			action: string;
			data: Record<string, unknown>;
		}) => {
			s.carolLogs.push(log);
		}
	);
	carol.on('payment:received', (payment: { paymentHash: Buffer }) => {
		s.received.push(payment);
	});
	carol.on('invoice:settled', (event: Record<string, unknown>) => {
		s.settled.push(event);
	});
}

/**
 * Open the world for bitcoin in, asset out, ready for Alice to pay Carol
 * in parts (payInParts). Carol's host opts in unless said.
 */
export async function openPartsScene(
	world: {
		open(tag: string, options: IForwardWorldOptions): Promise<IForwardWorld>;
		mine(world: IForwardWorld, blocks: number): Promise<void>;
	},
	tag: string,
	options: IPartsSceneOptions = {}
): Promise<IPartsScene> {
	const s = {
		shape: ['ordinary', 'asset'],
		asked: [],
		told: [],
		logs: [],
		forwarded: [],
		refused: [],
		carolAsks: [],
		carolLogs: [],
		received: [],
		settled: []
	} as unknown as IPartsScene;
	const value = setValuer({ topUp: options.topUp, quotes: options.quotes });
	s.carolHooks = {
		valueIncomingHtlc: (context): bigint | undefined => {
			s.carolAsks.push({
				...context,
				acceptedHtlcs: context.acceptedHtlcs.map((part) => ({ ...part }))
			});
			options.onCarolAsk?.(context, s);
			return value(context);
		},
		...(options.optIn === false ? {} : RECEIVE_IN_PARTS),
		...options.carol
	};
	const w = await world.open(tag, {
		kinds: { in: 'ordinary', out: 'asset' },
		feeWallet: { alice: true, bob: true, carol: true },
		...options.world,
		hooks: {
			bob: bobHooks(s, {
				answer: partsAnswer(options.quoteOf),
				...(options.bob ? { bob: options.bob } : {})
			}),
			carol: s.carolHooks
		}
	});
	s.w = w;
	for (const name of ['alice', 'bob', 'carol'] as const) {
		const coins =
			name === 'carol'
				? options.carolCoins ?? options.coins ?? 2
				: options.coins ?? 2;
		for (let i = 0; i < coins; i++) w.wallets[name]!.fund(100_000);
	}
	await world.mine(w, options.blocks ?? 1);
	listenBob(s as unknown as IScene);
	listenCarol(s);
	return s;
}
