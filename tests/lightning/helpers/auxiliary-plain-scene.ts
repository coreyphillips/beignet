/**
 * A plain HTLC on an asset channel: an HTLC that carries no units and no
 * custom records, which a peer offers on an asset channel as it would on an
 * ordinary one. This node never offers one, so the peer here is made to by
 * an add at the channel manager, with the asset side of the HTLC left out
 * (as auxiliary-payments.test.ts does). No engine payer keeps a record of
 * such an HTLC: what the peer's channel did with it is the payer's side.
 *
 * The wallet's host values such an HTLC at the bitcoin it carries when it
 * pays an invoice of the node, and an HTLC with units at 1000 msat a unit;
 * it answers "not mine" for anything else without units.
 */

import crypto from 'crypto';
import type { IChannelAuxiliaryProvider } from '../../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryIncomingHtlc
} from '../../../src/lightning/channel/auxiliary-funding';
import {
	HtlcState,
	type IHtlcEntry
} from '../../../src/lightning/channel/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../../src/lightning/onion/construct';
import { decryptFailureMessage } from '../../../src/lightning/onion/failures';
import { computeSharedSecrets } from '../../../src/lightning/onion/sphinx-crypto';
import type {
	ForwardChannelKind,
	IForwardWorld,
	IForwardWorldOptions
} from './auxiliary-forward-world';
import type { IAssetHost } from './auxiliary-nodes';

export const sha256 = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

export const hex = (value: Buffer): string => value.toString('hex');

/** The update messages of BOLT 2 that end an HTLC. */
export const UPDATE_FULFILL_HTLC = 130;
export const UPDATE_FAIL_HTLC = 131;
export const UPDATE_FAIL_MALFORMED_HTLC = 135;

/** What a host was asked, and the ends it was told of. */
export interface IPlainHostLog {
	asked: IAuxiliaryIncomingHtlc[];
	resolved: Array<Record<string, unknown>>;
}

export const plainHostLog = (): IPlainHostLog => ({ asked: [], resolved: [] });

/**
 * The wallet's host: an HTLC without units that arrived on an asset channel
 * and pays an invoice of the node is worth the bitcoin it carries; one with
 * units is worth 1000 msat a unit; anything else without units is not the
 * host's. Every ask and every end told is kept on `log`.
 */
export function plainValuer(log: IPlainHostLog): {
	valueIncomingHtlc: (context: IAuxiliaryIncomingHtlc) => bigint | undefined;
	onHtlcResolved: (context: unknown) => void;
} {
	return {
		valueIncomingHtlc: (context): bigint | undefined => {
			log.asked.push(context);
			if (context.auxiliaryAmount !== undefined) {
				return context.auxiliaryAmount * 1000n;
			}
			if (context.state.auxiliaryState !== undefined && context.invoice) {
				return context.wireAmountMsat;
			}
			return undefined;
		},
		onHtlcResolved: (context): void => {
			log.resolved.push(context as Record<string, unknown>);
		}
	};
}

/** The asks of a host about one payment hash. */
export const asksOf = (
	log: IPlainHostLog,
	paymentHash: Buffer
): IAuxiliaryIncomingHtlc[] =>
	log.asked.filter((ask) => ask.paymentHash.equals(paymentHash));

/** What one plain HTLC the peer offered is, and how to read what came back. */
export interface IPlainOffer {
	channelId: Buffer;
	htlcId: bigint;
	paymentHash: Buffer;
	amountMsat: bigint;
	cltvExpiry: number;
	/** The secrets the onion was built with, to read a failure the payee sent. */
	sharedSecrets: Buffer[];
}

export interface IPlainOfferOptions {
	/** The total the onion declares; the amount unless said. */
	totalMsat?: bigint;
	/** The payment secret the onion carries; none unless said. */
	paymentSecret?: Buffer;
	/** The custom records the HTLC carries, for one with units. */
	customRecords?: Map<bigint, Buffer>;
	/** A label the onion's session key is made from. */
	label?: string;
}

/**
 * `sender` offers `receiver` an HTLC of `amountMsat` on `channelId` at the
 * channel manager, its onion naming `receiver` as the final hop. On an
 * asset channel the HTLC is plain: no units and no custom records, unless
 * `customRecords` gives it units, which are then taken from the sender's
 * side as a host's own send would.
 */
export function offerHtlc(
	sender: IAssetHost,
	receiver: IAssetHost,
	channelId: Buffer,
	paymentHash: Buffer,
	amountMsat: bigint,
	cltvExpiry: number,
	options: IPlainOfferOptions = {}
): IPlainOffer {
	const manager = sender.node.getChannelManager();
	const channel = manager.getChannel(channelId);
	if (!channel) throw new Error('the sender has no such channel');
	const prepare = channel as unknown as {
		_prepareAuxiliaryHtlc: (...args: unknown[]) => unknown;
	};
	const own = Object.prototype.hasOwnProperty.call(
		prepare,
		'_prepareAuxiliaryHtlc'
	)
		? prepare._prepareAuxiliaryHtlc
		: undefined;
	if (
		channel.getFullState().auxiliaryState !== undefined &&
		!options.customRecords
	) {
		// The asset side of the HTLC is left out: a peer that offers a plain
		// HTLC on an asset channel.
		prepare._prepareAuxiliaryHtlc = (): undefined => undefined;
	}
	const pubkey = Buffer.from(receiver.node.getNodeId(), 'hex');
	const sessionKey = sha256(
		`plain session ${options.label ?? ''} ${hex(paymentHash)} ${hex(
			channelId
		)} ${channel.getFullState().localHtlcCounter}`
	);
	const packet = constructOnionPacket(
		sessionKey,
		[
			{
				pubkey,
				payload: {
					amountToForwardMsat: amountMsat,
					outgoingCltvValue: cltvExpiry,
					...(options.paymentSecret
						? {
								paymentSecret: options.paymentSecret,
								totalMsat: options.totalMsat ?? amountMsat
						  }
						: {})
				}
			}
		],
		paymentHash
	);
	const htlcId = channel.getFullState().localHtlcCounter;
	let added;
	try {
		added = manager.addHtlc(
			channelId,
			amountMsat,
			paymentHash,
			cltvExpiry,
			encodeOnionPacket(packet),
			undefined,
			undefined,
			...(options.customRecords
				? [{ customRecords: options.customRecords, expectedHtlcId: htlcId }]
				: [])
		);
	} finally {
		if (own) prepare._prepareAuxiliaryHtlc = own;
		else delete (prepare as Partial<typeof prepare>)._prepareAuxiliaryHtlc;
	}
	if (!added.ok) {
		throw new Error(`the HTLC was not added: ${added.error}`);
	}
	return {
		channelId,
		htlcId,
		paymentHash,
		amountMsat,
		cltvExpiry,
		sharedSecrets: computeSharedSecrets(sessionKey, [pubkey]).sharedSecrets
	};
}

/** An HTLC end a host sent its peer. */
export interface ISentEnd {
	type: number;
	channelId: Buffer;
	htlcId: bigint;
	/** The preimage of a fulfil. */
	preimage?: Buffer;
	/** The reason of a fail, as it was sent. */
	reason?: Buffer;
}

/** Every update a host sends from this call on that ends an HTLC, in order. */
export function endsSent(host: IAssetHost): ISentEnd[] {
	const sent: ISentEnd[] = [];
	host.node.on(
		'message:outbound',
		(_pubkey: string, type: number, payload: Buffer) => {
			if (
				type !== UPDATE_FULFILL_HTLC &&
				type !== UPDATE_FAIL_HTLC &&
				type !== UPDATE_FAIL_MALFORMED_HTLC
			) {
				return;
			}
			const end: ISentEnd = {
				type,
				channelId: Buffer.from(payload.subarray(0, 32)),
				htlcId: payload.readBigUInt64BE(32)
			};
			if (type === UPDATE_FULFILL_HTLC) {
				end.preimage = Buffer.from(payload.subarray(40, 72));
			} else if (type === UPDATE_FAIL_HTLC) {
				const length = payload.readUInt16BE(40);
				end.reason = Buffer.from(payload.subarray(42, 42 + length));
			}
			sent.push(end);
		}
	);
	return sent;
}

/** The ends sent of one HTLC. */
export const endsOfOffer = (sent: ISentEnd[], offer: IPlainOffer): ISentEnd[] =>
	sent.filter(
		(end) =>
			end.channelId.equals(offer.channelId) && end.htlcId === offer.htlcId
	);

/** The BOLT 4 failure code a fail sent for an offer carries, as its payer reads it. */
export function failureCodeOf(offer: IPlainOffer, end: ISentEnd): number {
	if (!end.reason) throw new Error('not a fail with a reason');
	const read = decryptFailureMessage(offer.sharedSecrets, end.reason);
	if (!read) throw new Error('the payer cannot read the failure');
	return read.failure.failureCode;
}

/** What a host decided for an HTLC it received on a channel. */
export const decisionOf = (
	host: IAssetHost,
	channelId: Buffer,
	htlcId: bigint
): string | undefined =>
	host.node.getChannelManager().auxiliaryHtlcDecision(channelId, htlcId)
		?.outcome;

/** Whether a host's channel manager knows a preimage of the hash: what its chain monitors are fed. */
export const monitorsKnow = (host: IAssetHost, paymentHash: Buffer): boolean =>
	(
		host.node.getChannelManager() as unknown as {
			_knownPreimages: Map<string, Buffer>;
		}
	)._knownPreimages.has(hex(paymentHash));

/** The HTLC entry a host's channel holds by key (`offered-<id>` or `received-<id>`). */
export const entryOf = (
	host: IAssetHost,
	channelId: Buffer,
	key: string
): IHtlcEntry | undefined =>
	host.node
		.getChannelManager()
		.getChannel(channelId)
		?.getFullState()
		.htlcs.get(key);

/** Whether a host's channel holds a committed HTLC by key. */
export const holds = (
	host: IAssetHost,
	channelId: Buffer,
	key: string
): boolean => entryOf(host, channelId, key)?.state === HtlcState.COMMITTED;

/** A host's bitcoin on its side of a channel. */
export const localMsat = (host: IAssetHost, channelId: Buffer): bigint =>
	host.node.getChannelManager().getChannel(channelId)!.getFullState()
		.localBalanceMsat;

/** The units on each side of an asset channel, as a host reads them. */
export const unitsOn = (
	host: IAssetHost,
	channelId: Buffer
): [bigint, bigint] => {
	const info = host.node.getAuxiliaryChannelInfo(channelId)!;
	return [info.localAssetBalance, info.remoteAssetBalance];
};

/** The parts of a hold invoice a host has parked. */
export const parkedOf = (host: IAssetHost, paymentHash: Buffer): number =>
	host.node
		.listHeldHtlcs()
		.filter((held) => held.paymentHash.equals(paymentHash))
		.reduce((sum, held) => sum + held.htlcCount, 0);

/** The parts a host collects for a hash, pending, in an MPP set. */
export const collectedOf = (host: IAssetHost, paymentHash: Buffer): number =>
	(
		(
			host.node as unknown as {
				pendingMppPayments: Map<
					string,
					{ receivedParts: Array<{ status: string }> }
				>;
			}
		).pendingMppPayments.get(hex(paymentHash))?.receivedParts ?? []
	).filter((part) => part.status === 'PENDING').length;

/** A structured log line of a node. */
export type Log = {
	category: string;
	action: string;
	data: Record<string, unknown>;
};

/** Every structured log a host emits from this call on. */
export function logsOf(host: IAssetHost): Log[] {
	const logs: Log[] = [];
	host.node.on('log', (log: Log) => logs.push(log));
	return logs;
}

/** Every hold event a host emits from this call on, by name, with its event. */
export function holdEventsOf(
	host: IAssetHost
): Array<{ name: string; event: Record<string, unknown> }> {
	const events: Array<{ name: string; event: Record<string, unknown> }> = [];
	for (const name of ['hold:accepted', 'hold:settled', 'hold:cancelled']) {
		host.node.on(
			name as never,
			((event: Record<string, unknown>) =>
				events.push({ name, event })) as never
		);
	}
	return events;
}

/** Message rounds until `reached`, or throw with what is missing. */
export async function until(
	what: string,
	reached: () => boolean,
	most = 40
): Promise<void> {
	for (let i = 0; i < most && !reached(); i++) {
		for (let j = 0; j < 40; j++) {
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
	}
	if (!reached()) throw new Error(`never reached: ${what}`);
}

/*
 * On the three-node world of auxiliary-forward-world.ts: Carol is the
 * wallet, with an asset channel from Bob (`outChannel`) and a second
 * channel from him (`outChannel2`), ordinary unless said, and Bob is the
 * peer that offers her plain HTLCs. Carol runs from a database file and
 * has a fee wallet; so has Bob.
 */

export interface IPlainWorld {
	w: IForwardWorld;
	log: IPlainHostLog;
	/** Carol's hooks, as she was opened with them, for a restart. */
	hooks: Partial<IAuxiliaryChannelConfig>;
}

export interface IPlainWorldOptions {
	/** The kind of Bob's second channel with Carol; ordinary unless said. */
	secondOut?: ForwardChannelKind;
	/** Put something between Carol and her provider. */
	wrapProvider?: (
		provider: IChannelAuxiliaryProvider
	) => IChannelAuxiliaryProvider;
	/** The fee coins of each fee wallet; 2 unless said. */
	coins?: number;
	/** Runs each time Carol's host is asked, ahead of its answer. */
	onAsk?: (context: IAuxiliaryIncomingHtlc, log: IPlainHostLog) => void;
}

export async function openPlainWorld(
	world: {
		open(tag: string, options: IForwardWorldOptions): Promise<IForwardWorld>;
		mine(world: IForwardWorld, blocks: number): Promise<void>;
	},
	tag: string,
	options: IPlainWorldOptions = {}
): Promise<IPlainWorld> {
	const log = plainHostLog();
	const valuer = plainValuer(log);
	const hooks: Partial<IAuxiliaryChannelConfig> = {
		valueIncomingHtlc: (context) => {
			options.onAsk?.(context, log);
			return valuer.valueIncomingHtlc(context);
		},
		onHtlcResolved:
			valuer.onHtlcResolved as IAuxiliaryChannelConfig['onHtlcResolved']
	};
	const w = await world.open(tag, {
		kinds: { in: 'ordinary', out: 'asset' },
		secondOut: options.secondOut ?? 'ordinary',
		carolOnFile: true,
		feeWallet: { bob: true, carol: true },
		hooks: { carol: hooks },
		...(options.wrapProvider
			? { wrapProvider: { carol: options.wrapProvider } }
			: {})
	});
	for (const name of ['bob', 'carol'] as const) {
		for (let i = 0; i < (options.coins ?? 2); i++) {
			w.wallets[name]!.fund(100_000);
		}
	}
	await world.mine(w, 1);
	return { w, log, hooks };
}

/** Bob offers Carol a plain HTLC on one of his channels with her. */
export function bobOffers(
	pw: IPlainWorld,
	channelId: Buffer,
	invoice: { paymentHash: Buffer; paymentSecret: Buffer },
	amountMsat: bigint,
	options: {
		totalMsat?: bigint;
		/** Blocks above the tip it expires at; 60 unless said. */
		expiryDelta?: number;
		label?: string;
	} = {}
): IPlainOffer {
	return offerHtlc(
		pw.w.hosts.bob,
		pw.w.hosts.carol,
		channelId,
		invoice.paymentHash,
		amountMsat,
		pw.w.chain.height + (options.expiryDelta ?? 60),
		{
			paymentSecret: invoice.paymentSecret,
			totalMsat: options.totalMsat ?? amountMsat,
			label: options.label
		}
	);
}

/** The HTLCs of a hash Bob has out on one of his channels. */
export const bobHasOut = (
	pw: IPlainWorld,
	channelId: Buffer,
	paymentHash: Buffer
): number =>
	[
		...(pw.w.hosts.bob.node
			.getChannelManager()
			.getChannel(channelId)
			?.getFullState().htlcs ?? new Map<string, IHtlcEntry>())
	].filter(
		([key, entry]) =>
			key.startsWith('offered-') && entry.paymentHash.equals(paymentHash)
	).length;
