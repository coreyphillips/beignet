/**
 * Two ChannelManagers over a ready final channel, linked by an in-memory peer
 * transport, for the #2151 Step 3a agreement tests (contract section 10).
 *
 * The pair is built on the stores of `plainTypePair` or `assetTypePair`
 * (generation 6 originals on both sides), then taken through
 * channel_reestablish, funding depth and, for an asset channel, the proof
 * import, so `updatesReady` (plain) or the asset update height (asset) holds
 * before a test begins.
 *
 * The link delivers each side's messages in order. A test can hold, drop or
 * inject a message, cut the connection at a named message, or script one
 * side by hand: a scripted side's manager is detached, the messages sent to
 * it land in `link.inbox`, and the test sends in its name with `link.send`.
 */
import { Transaction } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { createHash } from 'crypto';
import type Database from 'better-sqlite3';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import type {
	IAssetConversionContext,
	IAssetConversionTerms
} from '../../../src/lightning/channel';
import type { IAuxiliaryDualFunding } from '../../../src/lightning/channel/asset-opening-provider';
import { Feature, FeatureFlags } from '../../../src/lightning/features/flags';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../../src/lightning/message/custom';
import { expect } from 'chai';
import { MessageType } from '../../../src/lightning/message/types';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import type { TxidHex } from '../../../src/utils/identifiers';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../../src/lightning/features/asset-opening';
import * as spliceCodec from '../../../src/lightning/message/splice';
import { encodeStfuMessage } from '../../../src/lightning/message/stfu';
import { encodeTxAbortMessage } from '../../../src/lightning/message/interactive-tx';
import { completeRecoveryHost, finalTestNode } from './asset-conversion-node';
import { referenceProvider } from './auxiliary-pair';
import { assetUpdateTestHost } from './asset-splice-update';
import {
	assetTypePair,
	plainTypePair,
	FIT_TERMS,
	type Scratch
} from './channel-type-pairs';
import type { FinalGeneration } from './final-generation';
import type { IReadyPairTerms } from './final-update-pair';
import {
	conversionTerms,
	method,
	type ConversionPair,
	type IConversionBitcoin,
	type IConversionDescription,
	type IConversionPlan
} from './conversion-modules';
import { CONVERSION_HOST_KEYS } from './asset-conversion-node';

/** The height both managers run at once the pair is ready. */
export const PAIR_HEIGHT = 600_000;

// ---------------------------------------------------------------------------
// Wire names
// ---------------------------------------------------------------------------

/** Envelope phase bytes of the two conversion phases (contract section 8). */
export const CONVERSION_TERMS_PHASE = 7;
export const CONVERSION_REPLY_PHASE = 8;

/**
 * A short name for a wire message: the BOLT type's name (`STFU`, `SPLICE`,
 * `SPLICE_ACK`, `TX_ABORT`, ...), or for a beignet custom message
 * `conversion_terms`, `conversion_reply`, `asset_splice:<phase byte>`,
 * `asset_splice_consent`, `asset_update` or `custom:<subtype>`.
 */
export function wireName(type: number, payload: Buffer): string {
	if (type !== BEIGNET_CUSTOM_MESSAGE_TYPE)
		return MessageType[type] ?? 'type:' + type;
	let subtype: number, inner: Buffer;
	try {
		({ subtype, payload: inner } = decodeCustomMessage(payload));
	} catch {
		return 'custom:undecodable';
	}
	if (subtype === BeignetCustomSubtype.ASSET_UPDATE) return 'asset_update';
	if (subtype === BeignetCustomSubtype.ASSET_SPLICE_CONSENT)
		return 'asset_splice_consent';
	if (subtype !== BeignetCustomSubtype.ASSET_SPLICE) return 'custom:' + subtype;
	if (inner[1] === CONVERSION_TERMS_PHASE) return 'conversion_terms';
	if (inner[1] === CONVERSION_REPLY_PHASE) return 'conversion_reply';
	return 'asset_splice:' + inner[1];
}

/** The envelope payload (after the custom header) of a custom message. */
export function customPayload(raw: Buffer): { subtype: number; frame: Buffer } {
	const { subtype, payload } = decodeCustomMessage(raw);
	return { subtype, frame: payload };
}

/** Wrap an envelope frame as the ASSET_SPLICE custom message. */
export function assetSpliceCustom(frame: Buffer): Buffer {
	return encodeCustomMessage(BeignetCustomSubtype.ASSET_SPLICE, frame);
}

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

export interface IWireMessage {
	/** Side that sent it. */
	from: 0 | 1;
	type: number;
	payload: Buffer;
	name: string;
	/** Position in the link's send order (both sides). */
	seq: number;
}

export type WireMatch =
	| string
	| ((m: IWireMessage) => boolean)
	| { from: 0 | 1; name: string };

function matches(rule: WireMatch, m: IWireMessage): boolean {
	if (typeof rule === 'string') return m.name === rule;
	if (typeof rule === 'function') return rule(m);
	return m.from === rule.from && m.name === rule.name;
}

interface IRule {
	match: WireMatch;
	action: 'hold' | 'drop' | 'cut' | 'burst';
	once: boolean;
}

/**
 * In-order delivery between side 0 and side 1. `sent` is every message a
 * side put on the link (including dropped and held ones), `delivered` every
 * one that reached the other side's manager or inbox.
 */
export class PeerLink {
	readonly sent: IWireMessage[] = [];
	readonly delivered: IWireMessage[] = [];
	readonly held: IWireMessage[] = [];
	readonly dropped: IWireMessage[] = [];
	/** Messages addressed to a scripted side. */
	readonly inbox: [IWireMessage[], IWireMessage[]] = [[], []];
	readonly scripted: [boolean, boolean] = [false, false];
	connected = true;
	private readonly queue: IWireMessage[] = [];
	private rules: IRule[] = [];
	private seq = 0;
	private pumping = false;

	constructor(
		private readonly receive: (to: 0 | 1, m: IWireMessage) => void,
		private readonly onCut: () => void
	) {}

	/** Called by side `from`'s peer manager stub. */
	push(from: 0 | 1, type: number, payload: Buffer): void {
		const m: IWireMessage = {
			from,
			type,
			payload: Buffer.from(payload),
			name: wireName(type, payload),
			seq: this.seq++
		};
		this.sent.push(m);
		if (!this.connected) {
			this.dropped.push(m);
			return;
		}
		this.queue.push(m);
	}

	/** Hold every matching message (or only the next with once) until release(). */
	hold(match: WireMatch, once = false): void {
		this.rules.push({ match, action: 'hold', once });
	}
	drop(match: WireMatch, once = false): void {
		this.rules.push({ match, action: 'drop', once });
	}
	/** Disconnect both sides instead of delivering the next matching message. */
	cutAt(match: WireMatch): void {
		this.rules.push({ match, action: 'cut', once: true });
	}
	/**
	 * Deliver the next matching message together with every message queued
	 * right after it that also matches, in one synchronous turn: no
	 * setImmediate runs between them (step 3b contract, M1).
	 */
	burst(match: WireMatch): void {
		this.rules.push({ match, action: 'burst', once: true });
	}
	clearRules(): void {
		this.rules = [];
	}
	/** Deliver held messages (matching `match`, or all) ahead of the queue, in order. */
	release(match?: WireMatch): void {
		const out = this.held.filter((m) => !match || matches(match, m));
		for (const m of out) this.held.splice(this.held.indexOf(m), 1);
		this.queue.unshift(...out);
	}
	/** Deliver a message as if side `from` sent it, after anything queued. */
	inject(from: 0 | 1, type: number, payload: Buffer): void {
		this.push(from, type, payload);
	}
	/** Send in the name of a scripted side. */
	send(from: 0 | 1, type: number, payload: Buffer): void {
		this.push(from, type, payload);
	}
	/** Detach side i: messages to it go to inbox[i]. */
	script(i: 0 | 1): void {
		this.scripted[i] = true;
	}

	/** Deliver until nothing is queued and the managers' async work settled. */
	async flush(rounds = 400): Promise<void> {
		if (this.pumping) return;
		this.pumping = true;
		try {
			let idle = 0;
			for (let n = 0; n < rounds && idle < 8; n++) {
				const m = this.queue.shift();
				if (!m) {
					idle++;
					await settleOnce();
					continue;
				}
				idle = 0;
				const rule = this.rules.find((r) => matches(r.match, m));
				if (rule?.once) this.rules.splice(this.rules.indexOf(rule), 1);
				if (rule?.action === 'drop') {
					this.dropped.push(m);
					continue;
				}
				if (rule?.action === 'hold') {
					this.held.push(m);
					continue;
				}
				if (rule?.action === 'cut') {
					this.dropped.push(m, ...this.queue.splice(0));
					this.connected = false;
					this.onCut();
					continue;
				}
				const turn = [m];
				if (rule?.action === 'burst')
					while (this.queue.length && matches(rule.match, this.queue[0]))
						turn.push(this.queue.shift()!);
				for (const x of turn) {
					const to = (1 - x.from) as 0 | 1;
					this.delivered.push(x);
					if (this.scripted[to]) this.inbox[to].push(x);
					else this.receive(to, x);
				}
				await settleOnce();
			}
		} finally {
			this.pumping = false;
		}
	}

	/** Names of the delivered messages, in order, as `<from>:<name>`. */
	trace(filter?: (m: IWireMessage) => boolean): string[] {
		return this.delivered
			.filter((m) => !filter || filter(m))
			.map((m) => m.from + ':' + m.name);
	}
}

/** Let promise chains and immediates run once. */
export async function settleOnce(): Promise<void> {
	await new Promise<void>((done) => setImmediate(done));
}

// ---------------------------------------------------------------------------
// The conversion host stub
// ---------------------------------------------------------------------------

export type ConversionHostCallName =
	| 'conversionTerms'
	| 'verifyConversionTerms'
	| 'abandonConversion'
	| 'proposeConversion'
	| 'describeConversion'
	| 'prepareConversion';

export interface IConversionHostCall {
	side: 0 | 1;
	name: ConversionHostCallName;
	args: unknown[];
	/** Position across both hosts. */
	seq: number;
	/** Set when the call's promise settled. */
	settled?: boolean;
}

/** A promise that never settles: a host that never answers. */
export function never<T>(): Promise<T> {
	return new Promise<T>(() => undefined);
}

/**
 * Records every conversion host call (name, arguments, order across both
 * sides) and answers as the test chooses. `terms` returns the terms for
 * `conversionTerms`; `verify` answers `verifyConversionTerms` (true confirms;
 * return false, throw, or `never()` to decline); `abandon` answers
 * `abandonConversion`.
 */
export class ConversionHostStub {
	terms: (
		ctx: Omit<IAssetConversionContext, 'attempt'>,
		request: { reference: Buffer }
	) => IAssetConversionTerms | Promise<IAssetConversionTerms> = () => {
		throw new Error('The test chose no conversion terms');
	};
	verify: (
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms,
		digest: Buffer
	) => unknown = () => true;
	abandon: (ctx: IAssetConversionContext, reason: string) => unknown = () =>
		undefined;
	/** Answers proposeConversion: by default this side's fixed blob. */
	propose: (
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms
	) => unknown = () => stubProposal(this.side);
	/** Answers describeConversion: by default the stub layout of the pair. */
	describe: (
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin
	) => unknown = (ctx, _proposals, bitcoin) =>
		stubConversionDescription(ctx, this.termsFor(ctx), bitcoin);
	/** Answers prepareConversion: by default sha256 of the layout digest. */
	prepare: (
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin,
		layoutDigest: Buffer
	) => unknown = (_ctx, _proposals, _bitcoin, layoutDigest) => ({
		digest: createHash('sha256').update(layoutDigest).digest()
	});
	/** The terms this host was shown for each attempt (hex id). */
	private readonly shown = new Map<string, IAssetConversionTerms>();

	/** The terms this host verified or was asked to propose for, by the attempt. */
	termsFor(ctx: IAssetConversionContext): IAssetConversionTerms {
		const terms = this.shown.get(Buffer.from(ctx.attempt).toString('hex'));
		if (!terms)
			throw new Error('The stub host was shown no terms for this attempt');
		return terms;
	}

	constructor(
		readonly side: 0 | 1,
		readonly log: IConversionHostCall[]
	) {}

	private record<T>(
		name: ConversionHostCallName,
		args: unknown[],
		run: () => T
	): T {
		const call: IConversionHostCall = {
			side: this.side,
			name,
			args,
			seq: this.log.length
		};
		this.log.push(call);
		const out = run();
		if (out instanceof Promise)
			void out.then(
				() => (call.settled = true),
				() => (call.settled = true)
			);
		else call.settled = true;
		return out;
	}

	calls(name?: ConversionHostCallName): IConversionHostCall[] {
		return this.log.filter(
			(c) => c.side === this.side && (!name || c.name === name)
		);
	}

	/**
	 * The six conversion members (3a's three terms calls and 3b's three
	 * planner calls), each recorded in the shared log.
	 */
	members(): Pick<
		IAuxiliaryDualFunding,
		'conversionTerms' | 'verifyConversionTerms' | 'abandonConversion'
	> &
		IConversionHostPlanner {
		const show = (
			ctx: IAssetConversionContext,
			terms: IAssetConversionTerms
		): unknown =>
			this.shown.set(
				Buffer.from(ctx.attempt).toString('hex'),
				JSON.parse(JSON.stringify(terms)) as IAssetConversionTerms
			);
		return {
			conversionTerms: (
				ctx: Omit<IAssetConversionContext, 'attempt'>,
				request: { reference: Buffer }
			) =>
				this.record('conversionTerms', [ctx, request], () =>
					Promise.resolve().then(() => this.terms(ctx, request))
				),
			verifyConversionTerms: (
				ctx: IAssetConversionContext,
				terms: IAssetConversionTerms,
				digest: Buffer
			) =>
				this.record('verifyConversionTerms', [ctx, terms, digest], () => {
					show(ctx, terms);
					return Promise.resolve().then(
						() => this.verify(ctx, terms, digest) as boolean
					);
				}),
			abandonConversion: (ctx: IAssetConversionContext, reason: string) =>
				this.record('abandonConversion', [ctx, reason], () =>
					Promise.resolve().then(() => this.abandon(ctx, reason) as void)
				),
			proposeConversion: (
				ctx: IAssetConversionContext,
				terms: IAssetConversionTerms
			) =>
				this.record('proposeConversion', [ctx, terms], () => {
					show(ctx, terms);
					return Promise.resolve().then(
						() => this.propose(ctx, terms) as Buffer
					);
				}),
			describeConversion: (
				ctx: IAssetConversionContext,
				proposals: ConversionPair<Buffer>,
				bitcoin: IConversionBitcoin
			) =>
				this.record('describeConversion', [ctx, proposals, bitcoin], () =>
					Promise.resolve().then(
						() =>
							this.describe(ctx, proposals, bitcoin) as IConversionDescription
					)
				),
			prepareConversion: (
				ctx: IAssetConversionContext,
				proposals: ConversionPair<Buffer>,
				bitcoin: IConversionBitcoin,
				layoutDigest: Buffer
			) =>
				this.record(
					'prepareConversion',
					[ctx, proposals, bitcoin, layoutDigest],
					() =>
						Promise.resolve().then(
							() =>
								this.prepare(
									ctx,
									proposals,
									bitcoin,
									layoutDigest
								) as IConversionPlan
						)
				)
		};
	}
}

/** The planner members as the stub supplies them. */
export interface IConversionHostPlanner {
	proposeConversion(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms
	): Promise<Buffer>;
	describeConversion(
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin
	): Promise<IConversionDescription>;
	prepareConversion(
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin,
		layoutDigest: Buffer
	): Promise<IConversionPlan>;
}

/**
 * The host a pair's manager runs with: the complete recovery host (every
 * other callback throws), a proof import that succeeds, the asset update
 * signer of the fixtures, and, unless `conversion` is false, the stub's six
 * conversion members over the default version and margin (0, or `margin`).
 * Without `conversion` every conversion key is deleted: the six members,
 * `assetConversionVersion` and `conversionFeerateMarginPerKw`.
 */
function pairHost(
	i: 0 | 1,
	stub: ConversionHostStub,
	conversion: boolean,
	unexpected: string[],
	margin?: number
): IAuxiliaryDualFunding {
	const host: Record<string, unknown> = {
		...completeRecoveryHost(unexpected),
		confirmFunding: async () => undefined,
		retractFunding: async () => undefined,
		...assetUpdateTestHost(i, [], 1),
		retainAssetUpdatePeerViews: async () => undefined,
		...(conversion && stub.members()),
		...(conversion &&
			margin !== undefined && { conversionFeerateMarginPerKw: margin })
	};
	if (!conversion) for (const key of CONVERSION_HOST_KEYS) delete host[key];
	return host as unknown as IAuxiliaryDualFunding;
}

// ---------------------------------------------------------------------------
// The pair
// ---------------------------------------------------------------------------

let cachedInit: Buffer | undefined;
/**
 * A generation 6 node's live init, as a LightningNode over a generation 6
 * wallet with a complete recovery host advertises it (read once per
 * process), with or without 463.
 */
export function conversionInit(with463 = true): FeatureFlags {
	if (!cachedInit) {
		const n = finalTestNode(6);
		try {
			cachedInit = n.node.getLocalFeatures().toBuffer();
		} finally {
			n.close();
		}
	}
	const flags = FeatureFlags.fromBuffer(cachedInit);
	if (!with463) {
		flags.clearBit(Feature.OPTION_ASSET_CONVERSION);
		flags.clearBit(Feature.OPTION_ASSET_CONVERSION + 1);
	}
	return flags;
}

export interface IPairOptions {
	/** Generation of each side's wallet (default 6 on both). */
	generations?: [FinalGeneration, FinalGeneration];
	/** Opening terms of a plain pair (default FIT_TERMS). */
	terms?: IReadyPairTerms;
	/** Rounds before the managers start (plain: update_fee; asset: fee rounds). */
	rounds?: number;
	/**
	 * Side i's host lacks every conversion key: the six members, the version
	 * and the margin.
	 */
	withoutHostMembers?: [boolean, boolean];
	/**
	 * Side i's config.conversionFeerateEstimate in sat/kw: a function, or
	 * null to leave the field out. Default: 1000 sat/kw, which the default
	 * terms' feerate of 1000 meets at margin 0.
	 */
	conversionFeerateEstimate?: [
		FeerateEstimate | null | undefined,
		FeerateEstimate | null | undefined
	];
	/** Side i's host margin, conversionFeerateMarginPerKw (default 0). */
	conversionFeerateMarginPerKw?: [number | undefined, number | undefined];
	/** Side i's live init lacks 463. */
	without463?: [boolean, boolean];
	/** config.quiescenceTimeoutMs for both managers. */
	quiescenceTimeoutMs?: number;
	/** Stop before funding depth (an unconfirmed funding). */
	skipDepth?: boolean;
	/** false: never call handlePeerReconnected (the link stays silent). */
	connect?: boolean;
	/** Build the managers over these stores instead of a fresh pair. */
	existing?: {
		id: string;
		stores: SqliteStorage[];
		roots: BIP32Interface[];
		nodeIds: [string, string];
	};
}

/** config.conversionFeerateEstimate (step 3b contract, section 4 check 9). */
export type FeerateEstimate = () => Promise<number | null | undefined>;

/** The default estimate of a pair's sides, in sat/kw. */
export const PAIR_FEERATE_ESTIMATE = 1000;

export interface IConversionPair {
	kind: 'plain' | 'asset';
	/** Hex channel id. */
	id: string;
	channelId: Buffer;
	stores: SqliteStorage[];
	roots: BIP32Interface[];
	nodeIds: [string, string];
	managers: [ChannelManager, ChannelManager];
	hosts: [ConversionHostStub, ConversionHostStub];
	/** Every conversion host call of both sides, in order. */
	hostLog: IConversionHostCall[];
	/** Calls of the other host callbacks (all of which throw). */
	unexpected: string[];
	/** The host object each manager runs with; a test may replace a member. */
	dualFunding: [IAuxiliaryDualFunding, IAuxiliaryDualFunding];
	inits: [FeatureFlags, FeatureFlags];
	link: PeerLink;
	/** Contained 'error' events per side. */
	errors: [string[], string[]];
	/** Peers each side's manager asked the peer manager to recycle. */
	recycled: [string[], string[]];
	/** The opener's side (from side 0's opening record). */
	opener: 0 | 1;
	fundingTxid: TxidHex;
	/** Deliver until idle. */
	settle(): Promise<void>;
	/** Disconnect both sides (handlePeerDisconnected), nothing in flight survives. */
	disconnect(): void;
	/** Reconnect both sides and run channel_reestablish and readiness again. */
	reconnect(): Promise<void>;
	/** Rebuild side i's manager over its store, as after a restart. */
	/**
	 * Tear side i's manager down as a disconnect does, then build a new one
	 * from its store. `afterTeardown` runs between the two, so a test can
	 * tell the old manager's calls from the new one's.
	 */
	restart(i: 0 | 1, afterTeardown?: () => void): Promise<void>;
	/** Plain: updatesReady; asset: the asset update height. */
	ready(i: 0 | 1): boolean;
	/**
	 * What each side's config.conversionFeerateEstimate answers; a test may
	 * replace one. A side built with the option null has no estimate field.
	 */
	feerateEstimates: [FeerateEstimate, FeerateEstimate];
}

function txidOfHex(hex: string): TxidHex {
	return Transaction.fromHex(hex).getId() as TxidHex;
}

/**
 * A ready final channel of `kind` between two managers. Plain: the plain
 * final type with terms that fit the asset type (FIT_TERMS). Asset: the
 * recovery profile.
 */
export async function conversionPair(
	s: Scratch,
	kind: 'plain' | 'asset',
	options: IPairOptions = {}
): Promise<IConversionPair> {
	const generations = options.generations ?? [6, 6];
	let id: string, stores: SqliteStorage[], roots: BIP32Interface[];
	let nodeIds: [string, string];
	if (options.existing) {
		({ id, stores, roots, nodeIds } = options.existing);
	} else if (kind === 'plain') {
		if (generations[0] !== generations[1])
			throw new Error('A plain pair has one generation on both sides');
		const p = plainTypePair(
			s,
			options.rounds ?? 0,
			generations[0],
			options.terms ?? FIT_TERMS
		);
		id = p.id;
		stores = p.stores;
		roots = p.sides.map((side) => side.root);
		nodeIds = [p.sides[0].binding.nodeId, p.sides[1].binding.nodeId];
	} else {
		const g = generations[0];
		if (g !== generations[1] || (g !== 4 && g !== 5 && g !== 6))
			throw new Error('An asset pair has one generation of 4 to 6');
		const p = await assetTypePair(s, options.rounds ?? 0, g);
		id = p.id;
		stores = p.devices.map((d) => d.store);
		roots = p.devices.map((d) => d.root);
		nodeIds = [p.bindings[0].nodeId, p.bindings[1].nodeId];
	}
	const channelId = Buffer.from(id, 'hex');
	const hostLog: IConversionHostCall[] = [];
	const hosts: [ConversionHostStub, ConversionHostStub] = [
		new ConversionHostStub(0, hostLog),
		new ConversionHostStub(1, hostLog)
	];
	const unexpected: string[] = [];
	const inits: [FeatureFlags, FeatureFlags] = [
		conversionInit(!options.without463?.[0]),
		conversionInit(!options.without463?.[1])
	];
	const errors: [string[], string[]] = [[], []];
	const recycled: [string[], string[]] = [[], []];
	const managers: ChannelManager[] = [];
	const fundingTxid = txidOfHex(stores[0].loadFinalOpening(id)!.fundingTxHex);
	const opener: 0 | 1 = stores[0].loadFinalOpening(id)!.isInitiator ? 0 : 1;

	const deliver = (to: 0 | 1, m: IWireMessage): void => {
		const manager = managers[to];
		const peer = nodeIds[m.from];
		if (m.type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
			const { subtype, payload } = decodeCustomMessage(m.payload);
			if (
				subtype === BeignetCustomSubtype.ASSET_OPEN ||
				subtype === BeignetCustomSubtype.ASSET_OPEN_CONSENT ||
				subtype === BeignetCustomSubtype.ASSET_SPLICE ||
				subtype === BeignetCustomSubtype.ASSET_SPLICE_CONSENT ||
				subtype === BeignetCustomSubtype.ASSET_UPDATE
			)
				manager.handleAssetOpenFrame(peer, subtype, payload);
			return;
		}
		manager.handleMessage(peer, m.type, m.payload);
	};
	const disconnectBoth = (): void => {
		managers.forEach((m, i) => m.handlePeerDisconnected(nodeIds[1 - i]));
	};
	const link = new PeerLink(deliver, disconnectBoth);

	const dualFunding = [0, 1].map((i) =>
		pairHost(
			i as 0 | 1,
			hosts[i],
			!options.withoutHostMembers?.[i],
			unexpected,
			options.conversionFeerateMarginPerKw?.[i]
		)
	) as [IAuxiliaryDualFunding, IAuxiliaryDualFunding];
	const fixed: FeerateEstimate = async () => PAIR_FEERATE_ESTIMATE;
	const feerateEstimates: [FeerateEstimate, FeerateEstimate] = [
		options.conversionFeerateEstimate?.[0] ?? fixed,
		options.conversionFeerateEstimate?.[1] ?? fixed
	];
	const build = (i: 0 | 1): ChannelManager => {
		const manager = new ChannelManager({
			finalOpening: { storage: stores[i], root: roots[i] },
			verifyRemoteFundingInput: async () => 'unspent',
			persistence: { persist: () => 'committed' },
			localFeatures: inits[i],
			auxiliaryChannels: {
				provider: referenceProvider(),
				resolveIncoming: () => undefined,
				dualFunding: dualFunding[i]
			},
			...(options.conversionFeerateEstimate?.[i] !== null && {
				conversionFeerateEstimate: (): Promise<number | null | undefined> =>
					feerateEstimates[i]()
			}),
			...(options.quiescenceTimeoutMs !== undefined && {
				quiescenceTimeoutMs: options.quiescenceTimeoutMs
			})
		} as unknown as IChannelManagerConfig);
		const peerManager = {
			sendToPeer: (peer: string, type: number, payload: Buffer): void => {
				if (peer !== nodeIds[1 - i]) throw new Error('Unknown test peer');
				link.push(i, type, payload);
			},
			getPeer: (
				peer: string
			): { getRemoteInit(): { features: FeatureFlags } } | undefined =>
				peer === nodeIds[1 - i] && link.connected
					? {
							getRemoteInit: (): { features: FeatureFlags } => ({
								features: inits[1 - i]
							})
					  }
					: undefined,
			recyclePeer: (peer: string): void => {
				recycled[i].push(peer);
				if (link.connected) {
					link.connected = false;
					disconnectBoth();
				}
			},
			disconnectPeer: (peer: string): void => {
				recycled[i].push(peer);
				if (link.connected) {
					link.connected = false;
					disconnectBoth();
				}
			}
		};
		(manager as unknown as { peerManager: unknown }).peerManager = peerManager;
		manager.on('error', (_id: unknown, message: string) =>
			errors[i].push(String(message))
		);
		manager.handleNewBlock(PAIR_HEIGHT);
		return manager;
	};
	managers.push(build(0), build(1));
	// Before the stores close: end every attempt and timer the managers hold.
	s.closing(() => {
		for (const [i, m] of managers.entries()) {
			m.handlePeerDisconnected(nodeIds[1 - i]);
			m.stopAssetOpenings();
			m.removeAllListeners();
		}
	});

	const deepen = (i: 0 | 1): void => {
		const m = managers[i];
		if (kind === 'asset')
			m.observeAssetOpeningAnchor(id, true, undefined, PAIR_HEIGHT - 10);
		m.observeFinalFunding(id, fundingTxid, PAIR_HEIGHT - 10, false);
		m.handleFundingConfirmed(channelId, fundingTxid);
	};
	const connect = async (): Promise<void> => {
		link.connected = true;
		if (options.connect !== false) {
			managers.forEach((m, i) => m.handlePeerReconnected(nodeIds[1 - i]));
			await link.flush();
		}
		if (!options.skipDepth) {
			deepen(0);
			deepen(1);
		}
		await link.flush();
	};
	await connect();

	const pair: IConversionPair = {
		kind,
		id,
		channelId,
		stores,
		roots,
		nodeIds,
		managers: managers as [ChannelManager, ChannelManager],
		hosts,
		hostLog,
		unexpected,
		dualFunding,
		inits,
		link,
		errors,
		recycled,
		opener,
		fundingTxid,
		settle: () => link.flush(),
		disconnect(): void {
			link.connected = false;
			disconnectBoth();
		},
		reconnect: connect,
		async restart(i: 0 | 1, afterTeardown?: () => void): Promise<void> {
			managers[i].handlePeerDisconnected(nodeIds[1 - i]);
			managers[i].stopAssetOpenings();
			managers[i].removeAllListeners();
			afterTeardown?.();
			managers[i] = build(i);
			pair.managers[i] = managers[i];
			managers[1 - i].handlePeerDisconnected(nodeIds[i]);
			await connect();
		},
		ready(i: 0 | 1): boolean {
			const m = managers[i] as unknown as {
				finalTransport?: { updatesReady(id: string): boolean };
				assetUpdateHeight(id: string): number | undefined;
			};
			return kind === 'plain'
				? !!m.finalTransport?.updatesReady(id)
				: m.assetUpdateHeight(id) === PAIR_HEIGHT;
		},
		feerateEstimates
	};
	return pair;
}

/**
 * One pair shared by the tests of a describe, built by the first test that
 * asks for it rather than in a hook, so a setup failure fails each test on
 * its own instead of the whole describe.
 */
export function sharedPair(
	s: Scratch,
	kind: 'plain' | 'asset',
	options?: IPairOptions,
	prepare?: (p: IConversionPair) => void
): () => Promise<IConversionPair> {
	let built: Promise<IConversionPair> | undefined;
	return (): Promise<IConversionPair> =>
		(built ??= conversionPair(s, kind, options).then((p) => {
			prepare?.(p);
			return p;
		}));
}

// ---------------------------------------------------------------------------
// The conversion seams the contract leaves to the code (see the report)
// ---------------------------------------------------------------------------

/**
 * Side i's conversion transport: the manager's private field
 * `assetConversion` (contract v3.1 item 2), or undefined.
 */
export interface IConversionTransportView {
	start(channelId: string, request: { reference: Buffer }): Promise<void>;
	held(id: string): boolean;
}
export function conversionTransportOf(
	manager: ChannelManager
): IConversionTransportView | undefined {
	return (manager as unknown as { assetConversion?: IConversionTransportView })
		.assetConversion;
}

/**
 * The internal start call, `assetConversion.start(hex id, { reference })`.
 * It rejects with the end's text when the attempt ends before the terms are
 * sent, and otherwise resolves once they are sent (v3.1 item 2). A missing
 * transport comes back as a rejection, so a test reads it like any other end.
 */
export function startConversion(
	manager: ChannelManager,
	channelId: Buffer,
	request: { reference: Buffer }
): Promise<void> {
	try {
		const transport = conversionTransportOf(manager);
		if (!transport)
			throw new Error('not implemented: ChannelManager.assetConversion');
		return method<[string, { reference: Buffer }], Promise<void>>(
			transport,
			'start',
			'AssetConversionTransport'
		)(channelId.toString('hex'), request);
	} catch (error) {
		return Promise.reject(error);
	}
}

/** Whether side i holds the channel (section 6, "Holding the channel"). */
export function held(manager: ChannelManager, id: string): boolean {
	const transport = conversionTransportOf(manager);
	if (!transport)
		throw new Error('not implemented: ChannelManager.assetConversion');
	return method<[string], boolean>(
		transport,
		'held',
		'AssetConversionTransport'
	)(id);
}

/**
 * A start whose outcome the test reads later without awaiting it:
 * `settled` once the promise settles, `error` its rejection text.
 */
export function track(p: Promise<unknown>): {
	settled: boolean;
	error?: string;
	done: Promise<void>;
} {
	const t: { settled: boolean; error?: string; done: Promise<void> } = {
		settled: false,
		done: Promise.resolve()
	};
	t.done = p.then(
		() => {
			t.settled = true;
		},
		(e: unknown) => {
			t.settled = true;
			t.error = e instanceof Error ? e.message : String(e);
		}
	);
	return t;
}

// ---------------------------------------------------------------------------
// Terms derived from one side's own store (contract section 3)
// ---------------------------------------------------------------------------

export type Role = 'opener' | 'acceptor';
/** The plain target type, without the alias bit (contract section 2). */
export const PLAIN_TARGET_TYPE_HEX = '0100000000000000000000';
/** An issuance id used by the to-asset terms of a plain parent. */
export const SAMPLE_ASSET_ID = '4c'.repeat(32);
/** An agreement expiry far after the engine's clock, in unix seconds (v3.1 item 4). */
export const FAR_EXPIRY = 4_000_000_000;
/** The engine's clock in unix seconds. */
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);

export interface ITermsOptions {
	/** The role that gives (default the opener). */
	giver?: Role;
	reference?: Buffer;
	expiresAt?: number;
	lockDepth?: number;
	contributions?: { opener: string; acceptor: string };
	/** Each issuance amount (default '1000'). */
	amount?: string;
	feeratePerKw?: number;
}

/** The role side i holds in the channel's opening, from its own record. */
export function roleOf(store: SqliteStorage, id: string): Role {
	return store.loadFinalOpening(id)!.isInitiator ? 'opener' : 'acceptor';
}

/**
 * The parent's current height N (section 4): the plain ledger's local
 * height, or the asset update head's last committed number.
 */
export function parentHeight(
	store: SqliteStorage,
	id: string,
	kind: 'plain' | 'asset'
): bigint {
	return kind === 'plain'
		? store.loadFinalUpdateStatus(id)?.localHeight ?? 0n
		: store.assetSpliceUpdateHead(id).nextNumber - 1n;
}

/** The parent's current commitment feerate as section 3 check 7 reads it. */
export function parentCommitmentFeerate(
	store: SqliteStorage,
	id: string,
	kind: 'plain' | 'asset'
): number {
	const session = store.loadFinalOpeningSession(id)!;
	if (kind === 'plain') {
		// The ledger state `s` that termsFor reads (s.locked.feeratePerKw).
		const view = (
			store as unknown as {
				finalUpdateView(id: string): {
					views: { s: { locked: { feeratePerKw?: number } } }[];
				} | null;
			}
		).finalUpdateView(id);
		return (
			view?.views[0].s.locked.feeratePerKw ??
			session.terms.commitmentFeeratePerKw
		);
	}
	const head = store.assetSpliceUpdateHead(id) as unknown as {
		committed?: { feerate?: number };
	};
	return head.committed?.feerate ?? session.terms.commitmentFeeratePerKw;
}

/**
 * The parent's balances before the commitment fee and the anchors, from one
 * side's own store, as the step 3b parent reader takes its snapshot
 * (section 5): a plain parent's locked ledger state; an asset parent's
 * committed round member on the live funding, else the opening's
 * contributions.
 */
export function parentBalancesMsat(
	store: SqliteStorage,
	id: string
): { local: bigint; remote: bigint } {
	const current = store.loadFinalChannelType(id)!;
	if (current.type === 'plain') {
		const view = (
			store as unknown as {
				finalUpdateView(id: string): {
					views: { s: { locked: { local: string; peer: string } } }[];
				} | null;
			}
		).finalUpdateView(id);
		const locked = view?.views[0]?.s.locked;
		if (locked)
			return { local: BigInt(locked.local), remote: BigInt(locked.peer) };
	} else {
		const head = store.assetSpliceUpdateHead(id) as unknown as {
			committed?: {
				members: {
					fundingTxid: string;
					outputIndex: number;
					localRecovery: {
						localBalanceMsat: string;
						remoteBalanceMsat: string;
					};
				}[];
			};
		};
		const member = head.committed?.members.find(
			(m) =>
				m.fundingTxid === current.funding.txid &&
				m.outputIndex === current.funding.outputIndex
		);
		if (member)
			return {
				local: BigInt(member.localRecovery.localBalanceMsat),
				remote: BigInt(member.localRecovery.remoteBalanceMsat)
			};
	}
	const opening = store.loadFinalOpening(id)!;
	return {
		local: BigInt(opening.localContributionSats) * 1000n,
		remote: BigInt(opening.remoteContributionSats) * 1000n
	};
}

/**
 * Terms a correct engine accepts for the pair's channel, derived only from
 * `store` (one side's own records): roles from its opening record, the
 * parent from its current type, the channel parameters from its opening
 * terms and limits mapped to roles, and the commitment feerate as check 7
 * reads it.
 *
 * Step 3b: the amounts pass every layout check of section 4 against the
 * stub planner's description (`stubConversionDescription`). To an asset,
 * nobody contributes and the first commitment keeps the parent's balances.
 * To bitcoin, the buyer (the unit holder) contributes minus its withdrawal
 * of STUB_WITHDRAWAL_SATS and the fee of STUB_FEE_SATS, and its balance
 * drops by as much. The fee budget follows the funding payer, the giver.
 */
export function storeTerms(
	store: SqliteStorage,
	id: string,
	options: ITermsOptions = {}
): IAssetConversionTerms {
	const current = store.loadFinalChannelType(id)!;
	const session = store.loadFinalOpeningSession(id)!;
	const local = roleOf(store, id);
	const byRole = <T>(mine: T, theirs: T): { opener: T; acceptor: T } =>
		local === 'opener'
			? { opener: mine, acceptor: theirs }
			: { opener: theirs, acceptor: mine };
	const toAsset = current.type === 'plain';
	const giver = options.giver ?? 'opener';
	const amount = options.amount ?? '1000';
	const assetId = SAMPLE_ASSET_ID;
	const limits = session.updateLimits!;
	const byGiver = <T>(own: T, rest: T): { opener: T; acceptor: T } =>
		giver === 'opener'
			? { opener: own, acceptor: rest }
			: { opener: rest, acceptor: own };
	const contributions =
		options.contributions ??
		byGiver(
			toAsset ? '0' : String(-(STUB_WITHDRAWAL_SATS + STUB_FEE_SATS)),
			'0'
		);
	const parent = parentBalancesMsat(store, id);
	const parentByRole = byRole(parent.local, parent.remote);
	const balanceOf = (role: Role): string =>
		String(parentByRole[role] + BigInt(contributions[role]) * 1000n);
	return {
		version: 1,
		channelId: id,
		parent: {
			txid: current.funding.txid,
			outputIndex: current.funding.outputIndex,
			stateNumber: parentHeight(store, id, current.type).toString()
		},
		direction: toAsset ? 'to-asset' : 'to-plain',
		targetType: toAsset
			? ASSET_SPLICE_RECOVERY_TYPE_HEX
			: PLAIN_TARGET_TYPE_HEX,
		giver,
		candidate: {
			dustLimitSats: byRole(
				String(session.terms.localDustLimitSatoshis),
				String(session.terms.remoteDustLimitSatoshis)
			),
			maxAcceptedHtlcs: byRole(
				limits.local.maxAcceptedHtlcs,
				limits.remote.maxAcceptedHtlcs
			)
		},
		contributions,
		units: { holder: giver, issuances: [{ assetId, amount }] },
		firstCommitment: {
			commitmentFeeratePerKw: parentCommitmentFeerate(store, id, current.type),
			balanceMsat: {
				opener: balanceOf('opener'),
				acceptor: balanceOf('acceptor')
			},
			...(toAsset && {
				units: [
					{
						assetId,
						opener: giver === 'opener' ? amount : '0',
						acceptor: giver === 'acceptor' ? amount : '0'
					}
				]
			})
		},
		fees: {
			fundingPayer: giver,
			budgets: byGiver(String(STUB_BUDGET_SATS), '0'),
			feeratePerKw: options.feeratePerKw ?? 1000,
			...(!toAsset && { withdrawalPayer: giver })
		},
		agreement: {
			reference: (options.reference ?? Buffer.alloc(16, 0x5e)).toString('hex'),
			expiresAt: options.expiresAt ?? FAR_EXPIRY
		},
		lockDepth: options.lockDepth ?? 3
	};
}

/**
 * The bytes, D and the attempt id of terms (sections 3 and 6), computed here
 * from the contract's formulas, not by the code under test. `storeTerms`
 * writes its keys in the canonical order, so JSON.stringify of its result is
 * the canonical form; pass `bytes` for a hand-made form.
 */
export function termsIdentity(
	terms: IAssetConversionTerms,
	bytes = Buffer.from(JSON.stringify(terms), 'ascii'),
	initiator: Role = 'opener'
): { bytes: Buffer; digest: Buffer; attempt: Buffer } {
	const digest = createHash('sha256')
		.update(
			Buffer.concat([
				Buffer.from('beignet/asset-conversion/terms/v1\0', 'ascii'),
				bytes
			])
		)
		.digest();
	return {
		bytes,
		digest,
		attempt: attemptIdOf(
			terms.channelId,
			terms.parent.txid,
			terms.parent.outputIndex,
			digest,
			initiator
		)
	};
}

/** The engine's canonical form of terms, by the code under test. */
export function canonicalBytes(terms: IAssetConversionTerms): Buffer {
	return Buffer.from(
		JSON.stringify(conversionTerms().canonicalAssetConversionTerms(terms)),
		'ascii'
	);
}

/**
 * sha256('asset-conversion-attempt/v1\0' || id || txid (internal) || u32 BE
 * index || D || role), role 0x00 when the opening's opener initiates and
 * 0x01 when its acceptor does (amendment v3.5).
 */
export function attemptIdOf(
	channelId: string,
	displayTxid: string,
	outputIndex: number,
	digest: Buffer,
	initiator: Role = 'opener'
): Buffer {
	// Terms whose index is not a u32 have no attempt id of this form. Check 2
	// refuses them before the acceptor computes one, so any id serves.
	const index = Buffer.alloc(4);
	if (
		Number.isInteger(outputIndex) &&
		outputIndex >= 0 &&
		outputIndex <= 0xffffffff
	)
		index.writeUInt32BE(outputIndex);
	return createHash('sha256')
		.update(
			Buffer.concat([
				Buffer.from('asset-conversion-attempt/v1\0', 'ascii'),
				Buffer.from(channelId, 'hex'),
				Buffer.from(displayTxid, 'hex').reverse(),
				index,
				digest,
				Buffer.from([initiator === 'opener' ? 0 : 1])
			])
		)
		.digest();
}

// ---------------------------------------------------------------------------
// Envelope frames, written by hand (today's encoder knows phases 0 to 6)
// ---------------------------------------------------------------------------

export interface IRawFrame {
	phase: number;
	attempt: Buffer;
	digest: Buffer;
	total: number;
	offset: number;
	bytes: Buffer;
}

export function rawFrame(f: IRawFrame): Buffer {
	const head = Buffer.alloc(74);
	head[0] = 1;
	head[1] = f.phase;
	f.attempt.copy(head, 2);
	f.digest.copy(head, 34);
	head.writeUInt32BE(f.total, 66);
	head.writeUInt32BE(f.offset, 70);
	return Buffer.concat([head, f.bytes]);
}

export function parseFrame(raw: Buffer): IRawFrame {
	return {
		phase: raw[1],
		attempt: raw.subarray(2, 34),
		digest: raw.subarray(34, 66),
		total: raw.readUInt32BE(66),
		offset: raw.readUInt32BE(70),
		bytes: raw.subarray(74)
	};
}

/** The conversion_terms frames of `bytes` (one chunk per 32 KiB). */
export function termsFrames(
	attempt: Buffer,
	bytes: Buffer,
	digest = createHash('sha256').update(bytes).digest()
): Buffer[] {
	const out: Buffer[] = [];
	for (let offset = 0; offset < bytes.length; offset += 32 * 1024)
		out.push(
			assetSpliceCustom(
				rawFrame({
					phase: CONVERSION_TERMS_PHASE,
					attempt,
					digest,
					total: bytes.length,
					offset,
					bytes: bytes.subarray(offset, offset + 32 * 1024)
				})
			)
		);
	return out;
}

/** A conversion_reply: accept is [0x00], decline [0x01] || reason. */
export function replyMessage(
	attempt: Buffer,
	digest: Buffer,
	reason?: string
): Buffer {
	const bytes =
		reason === undefined
			? Buffer.of(0)
			: Buffer.concat([Buffer.of(1), Buffer.from(reason, 'utf8')]);
	return assetSpliceCustom(
		rawFrame({
			phase: CONVERSION_REPLY_PHASE,
			attempt,
			digest,
			total: bytes.length,
			offset: 0,
			bytes
		})
	);
}

/** A delivered or sent conversion_reply, read. */
export function readReply(m: IWireMessage): {
	attempt: string;
	digest: string;
	accept: boolean;
	reason?: string;
} {
	const f = parseFrame(customPayload(m.payload).frame);
	return {
		attempt: f.attempt.toString('hex'),
		digest: f.digest.toString('hex'),
		accept: f.bytes.length === 1 && f.bytes[0] === 0,
		...(f.bytes[0] === 1 && { reason: f.bytes.subarray(1).toString('utf8') })
	};
}

/** The terms a conversion_terms message (all its chunks) carried. */
export function readTerms(ms: IWireMessage[]): {
	attempt: string;
	digest: string;
	bytes: Buffer;
} {
	const frames = ms.map((m) => parseFrame(customPayload(m.payload).frame));
	return {
		attempt: frames[0].attempt.toString('hex'),
		digest: frames[0].digest.toString('hex'),
		bytes: Buffer.concat(frames.map((f) => f.bytes))
	};
}

export function stfu(id: Buffer, initiator: boolean): Buffer {
	return encodeStfuMessage({ channelId: id, initiator });
}
export function txAbort(id: Buffer, text: string): Buffer {
	return encodeTxAbortMessage({ channelId: id, data: Buffer.from(text) });
}
export function abortText(m: IWireMessage): string {
	return m.payload.subarray(34).toString('utf8');
}

/** The conversion value of the splice TLV (section 2). */
export interface IConversionValue {
	termsDigest: Buffer;
	targetType: Buffer;
}
type SpliceInit = spliceCodec.ISpliceMessage & {
	conversion?: IConversionValue;
};
type SpliceAck = spliceCodec.ISpliceAckMessage & {
	conversion?: IConversionValue;
};
export const encodeSpliceInit = spliceCodec.encodeSpliceMessage as (
	m: SpliceInit
) => Buffer;
export const decodeSpliceInit = spliceCodec.decodeSpliceMessage as (
	raw: Buffer
) => SpliceInit;
export const encodeSpliceAck = spliceCodec.encodeSpliceAckMessage as (
	m: SpliceAck
) => Buffer;
export const decodeSpliceAck = spliceCodec.decodeSpliceAckMessage as (
	raw: Buffer
) => SpliceAck;

// ---------------------------------------------------------------------------
// Table snapshots (test 5)
// ---------------------------------------------------------------------------

function rawDb(store: SqliteStorage): Database.Database {
	return (store as unknown as { db: Database.Database }).db;
}
const rowText = (row: unknown): string =>
	JSON.stringify(row, (_k, v: unknown) =>
		Buffer.isBuffer(v) ? Buffer.from(v).toString('hex') : v
	);

/** Every row of every table, as text. */
export function tableRows(store: SqliteStorage): Map<string, Set<string>> {
	const d = rawDb(store);
	const out = new Map<string, Set<string>>();
	for (const { name } of d
		.prepare("SELECT name FROM sqlite_master WHERE type='table'")
		.all() as { name: string }[])
		out.set(
			name,
			new Set(d.prepare(`SELECT * FROM "${name}"`).all().map(rowText))
		);
	return out;
}

/** Rows added or removed between two snapshots, as `<+|-> <table> <row>`. */
export function changedRows(
	before: Map<string, Set<string>>,
	after: Map<string, Set<string>>
): string[] {
	const out: string[] = [];
	for (const t of new Set([...before.keys(), ...after.keys()])) {
		const a = before.get(t) ?? new Set<string>();
		const b = after.get(t) ?? new Set<string>();
		for (const r of b) if (!a.has(r)) out.push('+ ' + t + ' ' + r);
		for (const r of a) if (!b.has(r)) out.push('- ' + t + ' ' + r);
	}
	return out.sort();
}

/** The wallet's allocated channel key index (the key allocation's one row). */
export function allocatedKeyIndex(store: SqliteStorage): number {
	return Number(
		(
			store as unknown as { loadMetadata(key: string): string | null }
		).loadMetadata('channel_key_index_allocated')
	);
}

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------

/** The texts each side's host was told at abandonConversion, in order. */
export function abandoned(pair: IConversionPair, side: 0 | 1): string[] {
	return pair.hosts[side]
		.calls('abandonConversion')
		.map((c) => c.args[1] as string);
}

/** Give both hosts terms derived from their own stores. */
export function agreeOnTerms(
	pair: IConversionPair,
	options: ITermsOptions = {}
): void {
	for (const i of [0, 1] as const) {
		pair.hosts[i].terms = (_ctx, request): IAssetConversionTerms =>
			storeTerms(pair.stores[i], pair.id, {
				...options,
				reference: request.reference
			});
	}
}

/** Run timers and the link until both settle (fake timers installed). */
export async function tick(
	pair: IConversionPair,
	clock: { tickAsync(ms: number): Promise<number> },
	ms: number
): Promise<void> {
	await clock.tickAsync(ms);
	await pair.settle();
}

/**
 * Make side i's barrier (the conversion's wait for the final and asset
 * update queues) wait until the returned function is called, as a queued
 * task that spans an I/O turn would.
 */
export function gateBarrier(p: IConversionPair, i: 0 | 1): () => void {
	const m = p.managers[i] as unknown as {
		finalTransport?: { settled(id: string): Promise<void> };
		assetUpdates?: { settled(id: string): Promise<void> };
	};
	let open!: () => void;
	const gate = new Promise<void>((done) => (open = done));
	const restore: (() => void)[] = [];
	for (const t of [m.finalTransport, m.assetUpdates]) {
		if (!t) continue;
		const original = t.settled.bind(t);
		t.settled = (id: string): Promise<void> => gate.then(() => original(id));
		restore.push(() => (t.settled = original));
	}
	return () => {
		for (const r of restore) r();
		open();
	};
}

/** The fence's text (step 3b contract, section 6). */
export const FENCE =
	'Asset conversion stops before its layout is signed in this build';

/** One update round on the parent, which must complete. */
export async function updateRound(p: IConversionPair): Promise<void> {
	if (p.kind === 'plain') {
		const height = (i: number): bigint =>
			p.stores[i].loadFinalUpdateStatus(p.id)!.localHeight;
		const before = [height(0), height(1)];
		const r = p.managers[p.opener].updateChannelFee(
			p.channelId,
			400 + Number(before[0])
		);
		expect(r.ok, r.error).to.equal(true);
		await p.settle();
		for (const i of [0, 1])
			expect(height(i) > before[i], 'height ' + i).to.equal(true);
		return;
	}
	const before = p.stores[0].assetSpliceUpdateHead(p.id).nextNumber;
	await p.managers[0].startAssetSpliceUpdate(p.channelId, [
		{ kind: 'fee', feeratePerKw: 1200 + Number(before) }
	]);
	await p.settle();
	for (const store of p.stores)
		expect(store.assetSpliceUpdateHead(p.id).nextNumber).to.equal(before + 1n);
}

// ---------------------------------------------------------------------------
// The stub planner (step 3b contract, section 8)
// ---------------------------------------------------------------------------

/** The fee each stub layout pays, all of it from the funding payer. */
export const STUB_FEE_SATS = 1000n;
/** The funding payer's fee budget in storeTerms. */
export const STUB_BUDGET_SATS = 2000n;
/** The seller's wallet coin, standing in for its asset input, to an asset. */
export const STUB_SELLER_COIN_SATS = 10_000n;
/** The buyer's withdrawal, to bitcoin: the asset pair's larger dust limit. */
export const STUB_WITHDRAWAL_SATS = 1000n;
/** The commitment record limit each holder declares, to an asset. */
export const STUB_RECORD_LIMITS: readonly { type: bigint; maxBytes: number }[] =
	[{ type: 65537n, maxBytes: 1024 }];

/** Side i's fixed proposal. */
export function stubProposal(side: 0 | 1): Buffer {
	return Buffer.from('stub conversion proposal ' + side, 'ascii');
}

const tagHash = (tag: string): Buffer =>
	createHash('sha256')
		.update('stub conversion ' + tag)
		.digest();

/** The seller's wallet coin: one P2TR output of STUB_SELLER_COIN_SATS. */
export function stubSellerCoin(): Transaction {
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(tagHash('coin input'), 0, 0xfffffffd);
	tx.addOutput(
		Buffer.concat([Buffer.from([0x51, 0x20]), tagHash('coin key')]),
		Number(STUB_SELLER_COIN_SATS)
	);
	return tx;
}

/**
 * Serials of the stub layout: the shared input 0 and the funding output 2,
 * then each side's own output and input by its parity.
 */
export const STUB_SERIALS = {
	shared: 0n,
	funding: 2n,
	initiator: { output: 4n, input: 6n },
	acceptor: { output: 3n, input: 1n }
} as const;

/**
 * The description the stub planner returns, derived from the context, the
 * terms the host was shown and the engine's bitcoin facts:
 * - to an asset, the seller (the unit holder) adds its wallet coin and a
 *   change output, and moves every unit of the terms into the funding
 *   output;
 * - to bitcoin, the buyer (the unit holder) withdraws to one output what its
 *   contribution leaves after the fee, and every unit of the parent moves
 *   there, split between the two holders as `parentUnits` says.
 * The funding payer pays STUB_FEE_SATS. Pairs are in initiator order.
 */
export function stubConversionDescription(
	ctx: IAssetConversionContext,
	terms: IAssetConversionTerms,
	bitcoin: IConversionBitcoin
): IConversionDescription {
	const openerInitiates = ctx.isInitiator === ctx.isOpener;
	const order = <T>(p: { opener: T; acceptor: T }): [T, T] =>
		openerInitiates ? [p.opener, p.acceptor] : [p.acceptor, p.opener];
	const spliceRole = (role: Role): 'initiator' | 'acceptor' =>
		(role === 'opener') === openerInitiates ? 'initiator' : 'acceptor';
	const holder = spliceRole(terms.units.holder);
	const rel = order(terms.contributions).map(BigInt) as [bigint, bigint];
	const own = holder === 'initiator' ? rel[0] : rel[1];
	const serials = STUB_SERIALS[holder];
	const bySerial = <T extends { serialId: bigint }>(a: T, b: T): number =>
		a.serialId < b.serialId ? -1 : 1;
	const shared = {
		serialId: STUB_SERIALS.shared,
		txid: Buffer.from(ctx.parent.txid, 'hex').reverse(),
		vout: ctx.parent.outputIndex,
		sequence: 0xfffffffd,
		isShared: true
	};
	const funding = {
		serialId: STUB_SERIALS.funding,
		kind: 'funding' as const,
		valueSats: bitcoin.parent.valueSats + rel[0] + rel[1],
		descriptorHash: tagHash('funding')
	};
	const common = {
		feeBudgets: order(terms.fees.budgets).map(BigInt),
		relativeSatoshis: rel
	};
	if (terms.direction === 'to-asset') {
		const coin = stubSellerCoin();
		return {
			inputs: [
				shared,
				{
					serialId: serials.input,
					txid: coin.getHash(),
					vout: 0,
					sequence: 0xfffffffd,
					isShared: false,
					prevTx: coin.toBuffer()
				}
			].sort(bySerial),
			outputs: [
				funding,
				{
					serialId: serials.output,
					kind: 'change' as const,
					valueSats: STUB_SELLER_COIN_SATS + own - STUB_FEE_SATS,
					descriptorHash: tagHash('change')
				}
			].sort(bySerial),
			movements: terms.units.issuances.map((i) => ({
				assetId: i.assetId,
				from: holder,
				outputSerial: STUB_SERIALS.funding,
				units: BigInt(i.amount)
			})),
			parentUnits: [],
			...common,
			commitmentRecordLimits: [
				STUB_RECORD_LIMITS.map((r) => ({ ...r })),
				STUB_RECORD_LIMITS.map((r) => ({ ...r }))
			]
		};
	}
	const split = (amount: string): [bigint, bigint] => {
		const all = BigInt(amount);
		return [all / 2n, all - all / 2n];
	};
	return {
		inputs: [shared],
		outputs: [
			funding,
			{
				serialId: serials.output,
				kind: 'withdrawal' as const,
				valueSats: -own - STUB_FEE_SATS,
				descriptorHash: tagHash('withdrawal')
			}
		].sort(bySerial),
		movements: terms.units.issuances.flatMap((i) => {
			const [initiator, acceptor] = split(i.amount);
			return [
				...(initiator > 0n
					? [
							{
								assetId: i.assetId,
								from: 'initiator' as const,
								outputSerial: serials.output,
								units: initiator
							}
					  ]
					: []),
				...(acceptor > 0n
					? [
							{
								assetId: i.assetId,
								from: 'acceptor' as const,
								outputSerial: serials.output,
								units: acceptor
							}
					  ]
					: [])
			];
		}),
		parentUnits: terms.units.issuances.map((i) => {
			const [initiator, acceptor] = split(i.amount);
			return { assetId: i.assetId, initiator, acceptor };
		}),
		...common
	};
}

// ---------------------------------------------------------------------------
// Layout frames and digests (step 3b contract, sections 2 and 4)
// ---------------------------------------------------------------------------

/** Envelope phase bytes of `layout` and `layout_ack`. */
export const LAYOUT_PHASE = 0;
export const LAYOUT_ACK_PHASE = 4;

/** The `layout` frames of an object (one chunk per 32 KiB), as custom messages. */
export function layoutFrames(
	attempt: Buffer,
	bytes: Buffer,
	digest = createHash('sha256').update(bytes).digest(),
	total = bytes.length
): Buffer[] {
	const out: Buffer[] = [];
	for (let offset = 0; offset < bytes.length; offset += 32 * 1024)
		out.push(
			assetSpliceCustom(
				rawFrame({
					phase: LAYOUT_PHASE,
					attempt,
					digest,
					total,
					offset,
					bytes: bytes.subarray(offset, offset + 32 * 1024)
				})
			)
		);
	return out;
}

/** A `layout_ack` carrying `digest`, as a custom message. */
export function layoutAckMessage(
	attempt: Buffer,
	digest: Buffer,
	bytes = Buffer.alloc(0)
): Buffer {
	return assetSpliceCustom(
		rawFrame({
			phase: LAYOUT_ACK_PHASE,
			attempt,
			digest,
			total: 0,
			offset: 0,
			bytes
		})
	);
}

/** The frame header of a delivered or sent envelope message. */
export function frameOf(m: IWireMessage): IRawFrame {
	return parseFrame(customPayload(m.payload).frame);
}

/** sha256('asset-conversion-agreement/v1\0' || layoutDigest || planDigest). */
export function agreementDigestOf(
	layoutDigest: Buffer,
	planDigest: Buffer
): Buffer {
	return createHash('sha256')
		.update(
			Buffer.concat([
				Buffer.from('asset-conversion-agreement/v1\0', 'ascii'),
				layoutDigest,
				planDigest
			])
		)
		.digest();
}

/**
 * The host calls of an attempt that reached the fence, I initiating: each
 * side's calls in order, and the order across the sides that section 3's
 * flow fixes. Calls of other attempts must not be in `calls`.
 */
export function expectFenceHostOrder(
	calls: IConversionHostCall[],
	I: 0 | 1
): void {
	const A = (1 - I) as 0 | 1;
	const names = (side: 0 | 1): string[] =>
		calls.filter((c) => c.side === side).map((c) => c.name);
	expect(names(I), 'initiator host calls').to.deep.equal([
		'conversionTerms',
		'verifyConversionTerms',
		'proposeConversion',
		'describeConversion',
		'prepareConversion',
		'abandonConversion'
	]);
	expect(names(A), 'acceptor host calls').to.deep.equal([
		'verifyConversionTerms',
		'proposeConversion',
		'describeConversion',
		'prepareConversion',
		'abandonConversion'
	]);
	const at = (side: 0 | 1, name: ConversionHostCallName): number =>
		calls.findIndex((c) => c.side === side && c.name === name);
	const before = (
		a: [0 | 1, ConversionHostCallName],
		b: [0 | 1, ConversionHostCallName]
	): void => {
		expect(
			at(...a) < at(...b),
			a.join(':') + ' before ' + b.join(':')
		).to.equal(true);
	};
	before([I, 'verifyConversionTerms'], [A, 'verifyConversionTerms']);
	before([A, 'verifyConversionTerms'], [I, 'proposeConversion']);
	before([I, 'proposeConversion'], [A, 'proposeConversion']);
	before([A, 'proposeConversion'], [I, 'describeConversion']);
	before([A, 'proposeConversion'], [A, 'describeConversion']);
	before([I, 'prepareConversion'], [A, 'abandonConversion']);
	before([A, 'prepareConversion'], [A, 'abandonConversion']);
	before([A, 'abandonConversion'], [I, 'abandonConversion']);
}
