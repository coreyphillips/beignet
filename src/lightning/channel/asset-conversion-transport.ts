/**
 * Agreeing on an asset conversion (#2151 steps 3a and 3b). Two generation 6
 * peers agree, before quiescence, on terms both hosts confirm by digest,
 * then quiesce and exchange `splice_init` and `splice_ack` carrying the
 * terms digest and the target type. Each side then sends its host's
 * proposal as its `layout`, builds and checks the layout the hosts
 * describe, and sends its agreement digest in `layout_ack`. Once the two
 * agree, the attempt stops at a fence before signing: the initiator sends
 * `tx_abort` and the channel goes on at its parent, unchanged.
 *
 * Every attempt lives in memory only. Nothing is replayed after a
 * reconnect, and a restart calls nothing. The only durable write is each
 * side's candidate funding key allocation.
 */
import { Transaction } from 'bitcoinjs-lib';
import { REGTEST_CHAIN_HASH } from '../chain/hashes';
import { MIN_FEERATE_PER_KW } from '../chain/types';
import { sha256 } from '../crypto/provider';
import { isValidPublicKey } from '../crypto/ecdh';
import { deriveChannelKeys } from '../keys/wallet-keys';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../features/asset-opening';
import { assetConversionNegotiated } from '../features/asset-conversion';
import type { FeatureFlags } from '../features/flags';
import {
	ASSET_OPEN_CHUNK_SIZE,
	ASSET_OPEN_OBJECT_LIMIT,
	AssetOpenObjectReceiver,
	decodeAssetOpenFrame,
	encodeAssetOpenFrame,
	type IAssetOpenFrame
} from '../message/asset-open';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../message/custom';
import { decodeBolt1String, encodeBolt1String } from '../message/field-rules';
import {
	decodeTxAbortMessage,
	encodeTxAbortMessage
} from '../message/interactive-tx';
import {
	decodeSpliceAckMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	encodeSpliceMessage
} from '../message/splice';
import { encodeStfuMessage } from '../message/stfu';
import { MessageType as M } from '../message/types';
import {
	finalBranchReaders,
	type IAssetConversionParent
} from '../storage/final-branch-readers';
import {
	ASSET_CONVERSION_TEXTS as T,
	assetConversionBytesDigest,
	assetConversionTermsFailure,
	canonicalAssetConversionTerms,
	type IAssetConversionExpectation,
	type IAssetConversionTerms
} from './asset-conversion-terms';
import {
	ASSET_CONVERSION_LAYOUT_TEXTS,
	assetConversionAgreementDigest,
	assetConversionLayoutDigest,
	checkConversionLayout,
	describedConversionLayout,
	type IAssetConversionLayout
} from './asset-conversion-layout';
import type {
	AssetOpenPair,
	IAssetConversionBitcoin,
	IAssetConversionContext,
	IAssetConversionHost
} from './asset-opening-provider';
import type { IFinalOpeningRuntime } from './final-opening-runtime';
import { isFinalCommitmentUpdate } from './final-commitment-transport';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

const NOT_OFFERED = 'Asset conversion is not offered by this node';
const NOT_CONNECTED = 'Asset conversion requires a connected peer';
const NOT_NEGOTIATED = 'Asset conversion is not negotiated with this peer';
const OTHER_ATTEMPT = 'Another conversion of this channel is in progress';
const DECLINED = 'Asset conversion host declined the terms';
const WITHDRAWN = 'Asset conversion withdrawn';
const TIMED_OUT = 'Asset conversion timed out';
const UNEXPECTED = 'Unexpected message during asset conversion';
const DISCONNECTED = 'Peer disconnected';
const PEER_FIRST = 'Peer started quiescence first';
const PEER_GOES_FIRST = "Peer's conversion of this channel goes first";
const FENCE =
	'Asset conversion stops before its layout is signed in this build';
const PEER_UPDATED = 'Peer updated the channel during conversion quiescence';
const KEY_FAILED = 'Asset conversion could not allocate a funding key';
const INIT_MISMATCH = 'Asset conversion splice_init does not match its terms';
const ACK_MISMATCH = 'Asset conversion splice_ack does not match its terms';
/** A local close or a requested exit. */
const CLOSED = 'Asset conversion ended by a close';
const TOO_SOON = 'Asset conversion repeats a withdrawn attempt too soon';
const PROPOSE = 'Asset conversion host could not propose';
const DESCRIBE = ASSET_CONVERSION_LAYOUT_TEXTS.describe;
const PREPARE = 'Asset conversion host could not prepare the layout';
const DISAGREE = 'Peers disagree on the asset conversion layout';
const FRAME = 'Invalid asset conversion layout frame';
const PREMATURE = 'Premature asset conversion acknowledgement';
const NO_ESTIMATE = 'Asset conversion requires a feerate estimate';
const BELOW_FLOOR = 'Asset conversion funding feerate is below the local floor';
const MARGIN = 'Invalid asset conversion feerate margin';

/** The plain target type, without the alias bit. */
const PLAIN_TARGET_TYPE_HEX = '0100000000000000000000';
const HOST_BOUND_MS = 15_000;
const REPLY_BOUND_MS = 30_000;
const PHASE_BOUND_MS = 15_000;
const DEFAULT_DEADLINE_MS = 60_000;
const TERMS_LIMIT = 65536;
const REASON_LIMIT = 200;

type State =
	// The initiator: before its terms are sent, then each step it took.
	| 'starting'
	| 'announced'
	| 'quiescing'
	| 'init-sent'
	// The acceptor: before its accept, then each step it took.
	| 'assessing'
	| 'accepted'
	| 'quiesced'
	// Either side: its own layout sent (#2151 step 3b).
	| 'laid-out'
	// Its own tx_abort sent, waiting for the echo.
	| 'aborting'
	// The acceptor's decline sent after its accept.
	| 'draining';

interface IAttempt {
	id: string;
	peer: string;
	initiator: boolean;
	state: State;
	held: boolean;
	attempt?: Buffer;
	digest?: Buffer;
	terms?: IAssetConversionTerms;
	bytes?: Buffer;
	reference?: string;
	ctx?: IAssetConversionContext;
	/** The initiator took the peer's accept or decline of its terms. */
	replied?: boolean;
	/** The host's verify call was reached, so the end is told to it. */
	verified: boolean;
	/** The acceptor sent its stfu(0). */
	ownStfu: boolean;
	/** The initiator received the peer's stfu(0). */
	peerStfu: boolean;
	/** The encoded splice_init and splice_ack. */
	init?: Buffer;
	ack?: Buffer;
	/** The local candidate funding key's index. */
	keyIndex?: number;
	/** The local host's proposal, then the peer's once assembled. */
	proposal?: Buffer;
	peerProposal?: Buffer;
	receiver?: AssetOpenObjectReceiver;
	/** The parent read at the proposal point. */
	snapshot?: IAssetConversionParent;
	layoutSent: boolean;
	layoutDigest?: Buffer;
	planDigest?: Buffer;
	agreement?: Buffer;
	/** The peer's layout_ack value. */
	peerAck?: Buffer;
	/** The side has sent its own tx_abort. */
	abortSent?: boolean;
	/** The text of the side's own tx_abort or decline, which its end repeats. */
	sent?: string;
	deadline?: ReturnType<typeof setTimeout>;
	reply?: ReturnType<typeof setTimeout>;
	phase?: ReturnType<typeof setTimeout>;
	chain: Promise<void>;
	ended: boolean;
	endText?: string;
}

interface IAssembly {
	attempt: Buffer;
	receiver: AssetOpenObjectReceiver;
	timer: ReturnType<typeof setTimeout>;
}

const HOST_MEMBERS = [
	'conversionTerms',
	'verifyConversionTerms',
	'abandonConversion',
	'proposeConversion',
	'describeConversion',
	'prepareConversion'
] as const;

const validMargin = (margin: unknown): margin is number =>
	Number.isSafeInteger(margin) &&
	(margin as number) >= 0 &&
	(margin as number) <= MAX_SPLICE_FEERATE_PERKW;

/** Whether a host has the whole conversion surface: version 1, a margin in bounds and the six members. */
export function completeAssetConversionHost(
	host: unknown
): host is IAssetConversionHost {
	const h = host as Partial<IAssetConversionHost> | null | undefined;
	return (
		!!h &&
		h.assetConversionVersion === 1 &&
		validMargin(h.conversionFeerateMarginPerKw) &&
		HOST_MEMBERS.every((name) => typeof h[name] === 'function')
	);
}

export interface IAssetConversionDeps {
	/** The node's live init. */
	localFeatures: () => FeatureFlags | undefined;
	/** The peer's live init. */
	remoteFeatures: (peer: string) => FeatureFlags | undefined;
	/** The final transport's connection for the channel is established. */
	connected: (id: string) => boolean;
	/** The live funding reached its depth. */
	hasDepth: (id: string) => boolean;
	/** A plain splice is quiescent or an asset splice is negotiating. */
	busy: (id: string) => boolean;
	/** Resolves once the final and asset update queues ran what they held. */
	settled: (id: string) => Promise<void>;
	height: () => number;
	send: (peer: string, type: number, payload: Buffer) => void;
	disconnect: (peer: string) => void;
	report: (id: string, reason: string) => void;
	/** The quiescence deadline. */
	timeoutMs?: number;
	/** The local funding feerate estimate in sat/kw; none counts as no estimate. */
	feerateEstimate?: () => Promise<number | null | undefined>;
}

const message = (error: unknown): string =>
	error instanceof Error ? error.message : String(error);
const roleOf = (opener: boolean): 'opener' | 'acceptor' =>
	opener ? 'opener' : 'acceptor';
const unref = (timer: ReturnType<typeof setTimeout>): void => {
	(timer as { unref?: () => void }).unref?.();
};
const termsCopy = (terms: IAssetConversionTerms): IAssetConversionTerms =>
	JSON.parse(JSON.stringify(terms)) as IAssetConversionTerms;

/**
 * sha256('asset-conversion-attempt/v1\0' || id || txid (internal order) ||
 * u32 BE index || D || role), where role is 0x00 when the opening's opener
 * initiates and 0x01 when its acceptor does. The two sides' attempts on one
 * agreement therefore never share an id (amendment v3.5).
 */
function attemptId(
	id: string,
	txid: string,
	outputIndex: number,
	digest: Buffer,
	openerInitiates: boolean
): Buffer {
	const index = Buffer.alloc(4);
	index.writeUInt32BE(outputIndex);
	return sha256(
		Buffer.concat([
			Buffer.from('asset-conversion-attempt/v1\0', 'ascii'),
			Buffer.from(id, 'hex'),
			Buffer.from(txid, 'hex').reverse(),
			index,
			digest,
			Buffer.from([openerInitiates ? 0 : 1])
		])
	);
}

/** The key of a withdrawn attempt: its channel and its attempt id. */
const withdrawnKey = (id: string, attempt: Buffer): string =>
	id + ':' + attempt.toString('hex');

/** A received decline reason, or its bytes escaped when the BOLT 1 rules refuse it. */
function declineReason(bytes: Buffer): string {
	try {
		return decodeBolt1String(bytes, 'conversion_reply reason');
	} catch {
		return Array.from(bytes, (b) =>
			b >= 0x20 && b < 0x7f && b !== 0x5c
				? String.fromCharCode(b)
				: '\\x' + b.toString(16).padStart(2, '0')
		).join('');
	}
}

/**
 * The conversion side of a channel manager. Without the generation 6
 * original wallet, the final transport and the three host members it
 * offers nothing: it answers terms with a decline and holds nothing.
 */
export class AssetConversionTransport {
	private readonly attempts = new Map<string, IAttempt>();
	private readonly assembling = new Map<string, IAssembly>();
	/** The no-transport responder's last attempt answered, per peer. */
	private readonly answered = new Map<string, string>();
	/**
	 * Attempts the initiator ended in `announced` before any reply, by
	 * channel and attempt id, each for the reply bound. The peer's reply may
	 * still be on the wire, and identical terms from this side give the same
	 * attempt id, so a retry of them could take that stale reply as its own.
	 */
	private readonly withdrawn = new Map<
		string,
		{ peer: string; attempt: Buffer; timer: ReturnType<typeof setTimeout> }
	>();

	constructor(
		private readonly runtime: IFinalOpeningRuntime | undefined,
		private readonly host: IAssetConversionHost | undefined,
		private readonly deps: IAssetConversionDeps
	) {}

	private get offered(): boolean {
		return !!this.runtime && !!this.host;
	}

	/** Whether local starts of adds, fee updates, splices and conversions are refused. */
	held(id: string): boolean {
		return !!this.attempts.get(id)?.held;
	}

	// ---- The initiator's start ----

	/**
	 * Start a conversion of `channelId` (hex) under the host's agreement
	 * `reference`. Rejects with the end's text when the attempt ends before
	 * its terms are sent, and resolves once they are sent.
	 */
	async start(
		channelId: string,
		request: { reference: Buffer }
	): Promise<void> {
		const id = channelId;
		if (!this.offered || !this.host) throw new Error(NOT_OFFERED);
		const storage = this.runtime!.storage;
		const session =
			typeof id === 'string' && /^[0-9a-f]{64}$/.test(id)
				? storage.loadFinalOpeningSession(id)
				: null;
		if (!session || !this.deps.connected(id)) throw new Error(NOT_CONNECTED);
		if (!this.negotiated(id, session.peer)) throw new Error(NOT_NEGOTIATED);
		if (this.attempts.has(id)) throw new Error(T.held);
		if (!Buffer.isBuffer(request?.reference)) throw new Error(T.reference);
		const a = this.open(id, session.peer, true);
		a.reference = request.reference.toString('hex');
		const host = this.host;
		try {
			await this.barrier(a);
			this.live(a);
			let parent = this.preconditions(id);
			const base = this.context(a, parent);
			const proposed = await this.hostCall(() =>
				host.conversionTerms(
					{ ...base, parent: { ...base.parent } },
					{
						reference: Buffer.from(request.reference)
					}
				)
			);
			this.live(a);
			if (!proposed.ok) throw new Error(DECLINED);
			let terms: IAssetConversionTerms;
			try {
				terms = canonicalAssetConversionTerms(proposed.value);
			} catch {
				throw new Error(T.invalid);
			}
			const failure = assetConversionTermsFailure(
				terms,
				this.expectation(id, parent, a.reference),
				Date.now()
			);
			if (failure) throw new Error(failure);
			a.terms = terms;
			a.bytes = Buffer.from(JSON.stringify(terms), 'utf8');
			a.digest = assetConversionBytesDigest(a.bytes);
			a.attempt = attemptId(
				id,
				parent.txid,
				parent.outputIndex,
				a.digest,
				parent.opener
			);
			if (this.withdrawn.has(withdrawnKey(id, a.attempt)))
				throw new Error(TOO_SOON);
			const floor = await this.floorFailure(terms);
			this.live(a);
			if (floor) throw new Error(floor);
			a.ctx = { ...base, attempt: Buffer.from(a.attempt) };
			a.verified = true;
			const verdict = await this.hostCall(() =>
				host.verifyConversionTerms(
					this.ctxCopy(a),
					JSON.parse(JSON.stringify(terms)) as IAssetConversionTerms,
					Buffer.from(a.digest!)
				)
			);
			this.live(a);
			if (!verdict.ok || verdict.value !== true) throw new Error(DECLINED);
			await this.barrier(a);
			this.live(a);
			parent = this.preconditions(id);
			this.recheck(a, parent);
			this.sendTerms(a);
			a.state = 'announced';
			a.reply = this.timer(REPLY_BOUND_MS, () =>
				this.enqueue(a, () => {
					if (a.state === 'announced') this.fail(a, WITHDRAWN);
				})
			);
		} catch (error) {
			if (!a.ended) this.end(a, message(error));
			throw new Error(a.endText);
		}
	}

	// ---- Routing ----

	/**
	 * A peer message the channel's attempt owns in its state. An `STFU`
	 * that the initiator's announced state only observes is shown here and
	 * then left to today's routing.
	 */
	handle(peer: string, type: number, payload: Buffer): boolean {
		if (payload.length < 32) return false;
		const a = this.attempts.get(payload.subarray(0, 32).toString('hex'));
		if (!a || a.peer !== peer || !this.owns(a, type)) return false;
		if (a.state === 'announced') {
			// Observed only.
			if (payload.length === 33 && payload[32] === 1) this.end(a, PEER_FIRST);
			return false;
		}
		if (type === M.TX_ABORT) {
			// Taken at once, not behind the attempt's queue.
			this.peerAbort(a, payload);
			return true;
		}
		if (
			a.state === 'accepted' &&
			type === M.STFU &&
			payload.length === 33 &&
			payload[32] === 1
		)
			// The acceptor owns all from here.
			a.state = 'quiesced';
		if (
			a.state === 'quiescing' &&
			type === M.STFU &&
			payload.length === 33 &&
			payload[32] === 0
		)
			// The observer covers the initiator from here.
			a.peerStfu = true;
		const raw = Buffer.from(payload);
		this.enqueue(a, () => this.receive(a, type, raw));
		return true;
	}

	/**
	 * A peer's update in the quiet window: the attempt sends `tx_abort` and
	 * goes aborting, and the update is then delivered as today. Called for
	 * every peer message before any other routing.
	 */
	observe(peer: string, type: number, payload: Buffer): void {
		if (
			!isFinalCommitmentUpdate(type) &&
			type !== M.COMMITMENT_SIGNED &&
			type !== M.REVOKE_AND_ACK &&
			type !== M.START_BATCH
		)
			return;
		this.observeChannel(peer, payload);
	}

	/** An `ASSET_UPDATE` frame, which begins with its channel id. */
	observeAssetUpdate(peer: string, raw: Buffer): void {
		this.observeChannel(peer, raw);
	}

	private observeChannel(peer: string, payload: Buffer): void {
		if (payload.length < 32) return;
		const a = this.attempts.get(payload.subarray(0, 32).toString('hex'));
		if (
			!a ||
			a.peer !== peer ||
			!(
				(a.state === 'quiescing' && a.peerStfu) ||
				a.state === 'init-sent' ||
				a.state === 'laid-out' ||
				(a.state === 'quiesced' && a.ownStfu)
			)
		)
			return;
		this.abort(a, PEER_UPDATED);
	}

	/**
	 * Whether a subtype 98 frame names a live attempt of the peer's that
	 * owns envelope frames: the initiator's in `init-sent`, or either side's
	 * in `laid-out`. Side-effect free.
	 */
	ownsFrame(peer: string, raw: Buffer): boolean {
		return !!this.frameOwner(peer, raw);
	}

	private frameOwner(peer: string, raw: Buffer): IAttempt | undefined {
		if (!Buffer.isBuffer(raw) || raw.length < 34) return undefined;
		const attempt = raw.subarray(2, 34);
		for (const a of this.attempts.values())
			if (
				a.peer === peer &&
				!a.ended &&
				!!a.attempt?.equals(attempt) &&
				(a.state === 'laid-out' || (a.initiator && a.state === 'init-sent'))
			)
				return a;
		return undefined;
	}

	/**
	 * A conversion envelope frame of subtype 98: terms and replies (phase
	 * byte 7 or 8), or a layout or layout_ack (0 or 4) the attempt owns.
	 */
	custom(peer: string, raw: Buffer): void {
		const owner =
			raw[1] === 0 || raw[1] === 4 ? this.frameOwner(peer, raw) : undefined;
		if (owner) {
			const frame = Buffer.from(raw);
			this.enqueue(owner, () => this.receiveFrame(owner, frame));
			return;
		}
		let f: IAssetOpenFrame;
		try {
			f = decodeAssetOpenFrame(raw);
		} catch {
			return;
		}
		if (f.phase === 'conversion_reply') {
			this.receiveReply(peer, f);
			return;
		}
		if (f.phase !== 'conversion_terms') return;
		if (!this.offered) {
			// Once per attempt, on the frame at offset 0.
			const attempt = f.attempt.toString('hex');
			if (f.offset !== 0 || this.answered.get(peer) === attempt) return;
			this.answered.set(peer, attempt);
			this.sendReply(peer, f.attempt, f.digest, NOT_OFFERED);
			return;
		}
		this.assemble(peer, f);
	}

	// ---- Lifecycle ----

	/** Every attempt of the peer ends; nothing is sent. */
	disconnected(peer: string): void {
		this.answered.delete(peer);
		this.dropAssembly(peer);
		for (const a of [...this.attempts.values()])
			if (a.peer === peer) this.end(a, DISCONNECTED);
		// A reply from the old connection can no longer arrive.
		for (const [key, w] of [...this.withdrawn])
			if (w.peer === peer) this.forgetWithdrawn(key);
	}

	/** Every attempt ends; nothing is sent. */
	destroy(): void {
		for (const peer of [...this.assembling.keys()]) this.dropAssembly(peer);
		this.answered.clear();
		for (const a of [...this.attempts.values()]) this.end(a, DISCONNECTED);
		for (const key of [...this.withdrawn.keys()]) this.forgetWithdrawn(key);
	}

	/** A local close or a requested exit ends the channel's attempt by the failure rule. */
	closed(id: string): void {
		const a = this.attempts.get(id);
		if (a) this.fail(a, CLOSED);
	}

	// ---- The acceptor ----

	private assemble(peer: string, f: IAssetOpenFrame): void {
		let assembly = this.assembling.get(peer);
		if (assembly && !assembly.attempt.equals(f.attempt)) {
			// One object per peer: the first is kept.
			if (f.offset === 0)
				this.sendReply(
					peer,
					f.attempt,
					f.digest,
					'Asset conversion terms are already arriving'
				);
			return;
		}
		if (!assembly) {
			if (f.offset !== 0) return;
			assembly = {
				attempt: Buffer.from(f.attempt),
				receiver: new AssetOpenObjectReceiver(
					f.attempt,
					'conversion_terms',
					TERMS_LIMIT
				),
				timer: this.timer(this.deadlineMs, () => this.dropAssembly(peer))
			};
			this.assembling.set(peer, assembly);
		}
		let bytes: Buffer | undefined;
		try {
			bytes = assembly.receiver.receive(f);
		} catch {
			this.dropAssembly(peer);
			this.sendReply(peer, f.attempt, f.digest, T.invalid);
			return;
		}
		if (!bytes) return;
		this.dropAssembly(peer);
		this.receiveTerms(peer, Buffer.from(f.attempt), bytes);
	}

	private dropAssembly(peer: string): void {
		const assembly = this.assembling.get(peer);
		if (!assembly) return;
		clearTimeout(assembly.timer);
		this.assembling.delete(peer);
	}

	private receiveTerms(peer: string, attempt: Buffer, bytes: Buffer): void {
		const storage = this.runtime!.storage;
		const digest = assetConversionBytesDigest(bytes);
		let parsed: unknown;
		try {
			parsed = JSON.parse(bytes.toString('utf8'));
		} catch {
			return;
		}
		const id = (parsed as { channelId?: unknown } | null)?.channelId;
		// Terms naming a channel that is not the sender's are dropped silently.
		if (
			typeof id !== 'string' ||
			!/^[0-9a-f]{64}$/.test(id) ||
			storage.loadFinalOpeningSession(id)?.peer !== peer
		)
			return;
		const existing = this.attempts.get(id);
		if (existing) {
			if (
				existing.initiator &&
				(existing.state === 'starting' || existing.state === 'announced')
			) {
				// Crossing terms: the opening's opener's attempt continues.
				if (storage.loadFinalOpening(id)?.isInitiator) {
					this.sendReply(peer, attempt, digest, OTHER_ATTEMPT);
					return;
				}
				// Withdraw its own announced terms, so an opener that has no
				// attempt by the time they arrive does not take them up. The
				// ids are per side, so this names no attempt of the opener's.
				if (existing.state === 'announced')
					this.sendReply(peer, existing.attempt!, existing.digest!, WITHDRAWN);
				this.end(existing, PEER_GOES_FIRST);
			} else {
				const same =
					!!existing.attempt?.equals(attempt) &&
					!!existing.digest?.equals(digest);
				if (
					existing.state === 'aborting' ||
					existing.state === 'draining' ||
					(same &&
						(existing.state === 'assessing' || existing.state === 'accepted'))
				)
					return;
				this.sendReply(peer, attempt, digest, OTHER_ATTEMPT);
				return;
			}
		}
		let terms: IAssetConversionTerms;
		try {
			terms = canonicalAssetConversionTerms(parsed as IAssetConversionTerms);
			if (!Buffer.from(JSON.stringify(terms), 'utf8').equals(bytes))
				throw new Error(T.invalid);
		} catch {
			this.sendReply(peer, attempt, digest, T.invalid);
			return;
		}
		const a = this.open(id, peer, false);
		a.attempt = attempt;
		a.digest = digest;
		a.terms = terms;
		a.bytes = Buffer.from(bytes);
		this.enqueue(a, () => this.assess(a));
	}

	private async assess(a: IAttempt): Promise<void> {
		const host = this.host!;
		try {
			if (!this.deps.connected(a.id)) throw new Error(NOT_CONNECTED);
			if (!this.negotiated(a.id, a.peer)) throw new Error(NOT_NEGOTIATED);
			await this.barrier(a);
			this.live(a);
			let parent = this.preconditions(a.id);
			const failure = assetConversionTermsFailure(
				a.terms!,
				this.expectation(a.id, parent),
				Date.now()
			);
			if (failure) throw new Error(failure);
			// The peer initiates, so its role names the id.
			if (
				!attemptId(
					a.id,
					parent.txid,
					parent.outputIndex,
					a.digest!,
					!parent.opener
				).equals(a.attempt!)
			)
				throw new Error(T.invalid);
			const floor = await this.floorFailure(a.terms!);
			this.live(a);
			if (floor) throw new Error(floor);
			a.ctx = { ...this.context(a, parent), attempt: Buffer.from(a.attempt!) };
			a.verified = true;
			const verdict = await this.hostCall(() =>
				host.verifyConversionTerms(
					this.ctxCopy(a),
					JSON.parse(JSON.stringify(a.terms)) as IAssetConversionTerms,
					Buffer.from(a.digest!)
				)
			);
			this.live(a);
			if (!verdict.ok || verdict.value !== true) throw new Error(DECLINED);
			await this.barrier(a);
			this.live(a);
			parent = this.preconditions(a.id);
			this.recheck(a, parent);
		} catch (error) {
			if (a.ended) return;
			const text = message(error);
			this.sendReply(a.peer, a.attempt!, a.digest!, text);
			this.end(a, text);
			return;
		}
		a.state = 'accepted';
		a.held = true;
		this.armDeadline(a);
		this.sendReply(a.peer, a.attempt!, a.digest!);
	}

	// ---- Events ----

	private receiveReply(peer: string, f: IAssetOpenFrame): void {
		const a = [...this.attempts.values()].find(
			(x) => x.peer === peer && !!x.attempt?.equals(f.attempt)
		);
		const accept = f.bytes.length === 1 && f.bytes[0] === 0;
		const decline = f.bytes[0] === 1;
		if (!a) {
			// A decline is the peer's last reply for an attempt, so a withdrawn
			// one has nothing more on the wire once its decline arrived.
			if (decline)
				for (const [key, w] of [...this.withdrawn])
					if (w.peer === peer && w.attempt.equals(f.attempt))
						this.forgetWithdrawn(key);
			return;
		}
		if (!accept && !decline) return;
		if (!a.initiator) {
			// The initiator withdrew. The acceptor ends at once, not behind its
			// queue, so terms that follow in the same burst find no live attempt.
			if (decline && (a.state === 'assessing' || a.state === 'accepted'))
				this.end(a, WITHDRAWN);
			return;
		}
		// A decline is the peer's last reply for the attempt, even when an
		// end runs before the queued handler does.
		if (decline && a.state === 'announced') a.replied = true;
		const reason = decline ? declineReason(f.bytes.subarray(1)) : '';
		this.enqueue(a, async () => {
			if (a.state !== 'announced') return;
			if (decline) {
				a.replied = true;
				this.end(a, reason);
				return;
			}
			// An accept must carry D.
			if (!f.digest.equals(a.digest!)) return;
			a.replied = true;
			if (a.reply) clearTimeout(a.reply);
			a.reply = undefined;
			await this.barrier(a);
			if (a.ended || a.state !== 'announced') return;
			try {
				this.recheck(a, this.preconditions(a.id));
			} catch (error) {
				this.fail(a, message(error));
				return;
			}
			this.send(a, M.STFU, encodeStfuMessage(this.stfu(a, true)));
			a.state = 'quiescing';
		});
	}

	private async receive(
		a: IAttempt,
		type: number,
		payload: Buffer
	): Promise<void> {
		if (a.ended || a.state === 'aborting') return;
		if (a.state === 'draining') {
			// One answer: a side that has sent its tx_abort sends no other.
			if (type === M.STFU && payload[32] === 1 && !a.abortSent)
				this.sendAbort(a, WITHDRAWN);
			return;
		}
		const stfu =
			type === M.STFU && payload.length === 33 && payload[32] <= 1
				? payload[32]
				: undefined;
		switch (a.state) {
			case 'accepted':
				// stfu(0) from the initiator, before the acceptor's own.
				this.fail(a, UNEXPECTED);
				return;
			case 'quiescing':
				if (stfu === 0) await this.quiesced(a);
				else this.abort(a, UNEXPECTED);
				return;
			case 'init-sent':
				if (type === M.SPLICE_ACK) await this.acknowledged(a, payload);
				else this.abort(a, UNEXPECTED);
				return;
			case 'quiesced':
				if (!a.ownStfu && stfu === 1) await this.answerStfu(a);
				else if (a.ownStfu && type === M.SPLICE)
					await this.proposed(a, payload);
				else this.abort(a, UNEXPECTED);
				return;
			case 'laid-out':
				this.abort(a, UNEXPECTED);
				return;
		}
	}

	/**
	 * The peer's tx_abort, at once: in `aborting` or `draining` it ends the
	 * attempt with the side's own text, and a `draining` side that has sent
	 * no tx_abort answers it first; otherwise it is echoed with its data and
	 * the attempt ends with its text.
	 */
	private peerAbort(a: IAttempt, payload: Buffer): void {
		if (a.state === 'aborting' || a.state === 'draining') {
			if (a.state === 'draining' && !a.abortSent) this.sendAbort(a, WITHDRAWN);
			this.end(a, a.sent!);
			return;
		}
		let data: Buffer;
		try {
			data = decodeTxAbortMessage(payload).data;
		} catch {
			data = payload.subarray(32);
		}
		this.send(
			a,
			M.TX_ABORT,
			encodeTxAbortMessage({ channelId: this.channelId(a), data })
		);
		this.end(a, data.toString('utf8'));
	}

	/** I on the peer's stfu(0): checks, the proposal, key, splice_init. */
	private async quiesced(a: IAttempt): Promise<void> {
		await this.barrier(a);
		if (a.ended || a.state !== 'quiescing') return;
		try {
			this.recheck(a, this.preconditions(a.id));
		} catch (error) {
			this.fail(a, message(error));
			return;
		}
		const parent = await this.propose(a, 'quiescing');
		if (!parent) return;
		const key = this.fundingKey(a);
		if (!key) return;
		const t = a.terms!;
		const init = encodeSpliceMessage({
			channelId: this.channelId(a),
			relativeSatoshis: BigInt(t.contributions[roleOf(parent.opener)]),
			fundingFeeratePerkw: t.fees.feeratePerKw,
			locktime: this.deps.height(),
			fundingPubkey: key,
			lockDepth: t.lockDepth,
			conversion: this.conversion(a)
		});
		a.init = init;
		this.send(a, M.SPLICE, init);
		a.state = 'init-sent';
	}

	/** A on the initiator's stfu(1): checks, then its own stfu(0). */
	private async answerStfu(a: IAttempt): Promise<void> {
		await this.barrier(a);
		if (a.ended || a.state !== 'quiesced' || a.ownStfu) return;
		try {
			this.recheck(a, this.preconditions(a.id));
		} catch (error) {
			this.fail(a, message(error));
			return;
		}
		this.send(a, M.STFU, encodeStfuMessage(this.stfu(a, false)));
		a.ownStfu = true;
	}

	/** A on the initiator's splice_init: match, checks, the proposal, key, splice_ack and layout. */
	private async proposed(a: IAttempt, payload: Buffer): Promise<void> {
		const t = a.terms!;
		const opener = !!this.runtime!.storage.loadFinalOpening(a.id)?.isInitiator;
		let problem: string | undefined;
		try {
			const msg = decodeSpliceMessage(payload);
			problem = this.conversionProblem(a, msg.conversion, INIT_MISMATCH);
			if (
				!problem &&
				(!encodeSpliceMessage(msg).equals(payload) ||
					!isValidPublicKey(msg.fundingPubkey) ||
					msg.locktime > this.deps.height() + 1 ||
					msg.relativeSatoshis !== BigInt(t.contributions[roleOf(!opener)]) ||
					msg.fundingFeeratePerkw !== t.fees.feeratePerKw ||
					msg.lockDepth !== t.lockDepth ||
					msg.requireConfirmedInputs)
			)
				problem = INIT_MISMATCH;
		} catch {
			problem = INIT_MISMATCH;
		}
		if (problem) {
			this.abort(a, problem);
			return;
		}
		await this.barrier(a);
		if (a.ended || a.state !== 'quiesced') return;
		try {
			this.recheck(a, this.preconditions(a.id));
		} catch (error) {
			this.fail(a, message(error));
			return;
		}
		const parent = await this.propose(a, 'quiesced');
		if (!parent) return;
		const key = this.fundingKey(a);
		if (!key) return;
		const ack = encodeSpliceAckMessage({
			channelId: this.channelId(a),
			relativeSatoshis: BigInt(t.contributions[roleOf(parent.opener)]),
			fundingPubkey: key,
			lockDepth: t.lockDepth,
			conversion: this.conversion(a)
		});
		a.init = Buffer.from(payload);
		a.ack = ack;
		this.send(a, M.SPLICE_ACK, ack);
		this.sendLayout(a);
		a.state = 'laid-out';
	}

	/** I on the acceptor's splice_ack: its layout, or the ack's refusal. */
	private async acknowledged(a: IAttempt, payload: Buffer): Promise<void> {
		const t = a.terms!;
		const opener = !!this.runtime!.storage.loadFinalOpening(a.id)?.isInitiator;
		let problem: string | undefined;
		try {
			const msg = decodeSpliceAckMessage(payload);
			problem = this.conversionProblem(a, msg.conversion, ACK_MISMATCH);
			if (
				!problem &&
				(!encodeSpliceAckMessage(msg).equals(payload) ||
					!isValidPublicKey(msg.fundingPubkey) ||
					msg.relativeSatoshis !== BigInt(t.contributions[roleOf(!opener)]) ||
					msg.lockDepth !== t.lockDepth ||
					msg.requireConfirmedInputs)
			)
				problem = ACK_MISMATCH;
		} catch {
			problem = ACK_MISMATCH;
		}
		if (problem) {
			this.abort(a, problem);
			return;
		}
		a.ack = Buffer.from(payload);
		this.sendLayout(a);
		a.state = 'laid-out';
		// A layout of the acceptor's that arrived in init-sent is used now.
		if (a.peerProposal) await this.layoutSteps(a);
	}

	// ---- The proposal and the layout (#2151 step 3b) ----

	/**
	 * Check 9: the terms' funding feerate against the floor, the local
	 * estimate less the host's live margin. Its text, or undefined.
	 */
	private async floorFailure(
		terms: IAssetConversionTerms
	): Promise<string | undefined> {
		const margin = this.host?.conversionFeerateMarginPerKw;
		if (!validMargin(margin)) return MARGIN;
		const estimate = this.deps.feerateEstimate;
		const answer = estimate
			? await this.hostCall(estimate)
			: { ok: false as const };
		const value = answer.ok ? answer.value : undefined;
		if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
			return NO_ESTIMATE;
		if (terms.fees.feeratePerKw < Math.max(MIN_FEERATE_PER_KW, value - margin))
			return BELOW_FLOOR;
		return undefined;
	}

	/**
	 * A proposal point: the floor, the host's proposal, then the barrier and
	 * the re-check, whose parent is the snapshot. Undefined once the attempt
	 * failed, ended or left `state`; nothing is sent then.
	 */
	private async propose(
		a: IAttempt,
		state: 'quiescing' | 'quiesced'
	): Promise<IAssetConversionParent | undefined> {
		const host = this.host!;
		const floor = await this.floorFailure(a.terms!);
		if (!this.still(a, state)) return undefined;
		if (floor) {
			this.fail(a, floor);
			return undefined;
		}
		const ctx = this.ctxCopy(a);
		const terms = termsCopy(a.terms!);
		const proposal = await this.hostCall(() =>
			host.proposeConversion(ctx, terms)
		);
		if (!this.still(a, state)) return undefined;
		if (
			!proposal.ok ||
			!Buffer.isBuffer(proposal.value) ||
			proposal.value.length < 1 ||
			proposal.value.length > ASSET_OPEN_OBJECT_LIMIT
		) {
			this.fail(a, PROPOSE);
			return undefined;
		}
		a.proposal = Buffer.from(proposal.value);
		await this.barrier(a);
		if (!this.still(a, state)) return undefined;
		try {
			const parent = this.preconditions(a.id);
			this.recheck(a, parent);
			a.snapshot = parent;
			return parent;
		} catch (error) {
			this.fail(a, message(error));
			return undefined;
		}
	}

	/** A layout or layout_ack frame the attempt owns, in its queue. */
	private async receiveFrame(a: IAttempt, raw: Buffer): Promise<void> {
		if (a.state !== 'init-sent' && a.state !== 'laid-out') return;
		let bytes: Buffer | undefined;
		try {
			const f = decodeAssetOpenFrame(raw);
			if (f.phase === 'layout_ack') {
				this.peerLayoutAck(a, f.digest);
				return;
			}
			a.receiver ??= new AssetOpenObjectReceiver(
				a.attempt!,
				'layout',
				ASSET_OPEN_OBJECT_LIMIT
			);
			bytes = a.receiver.receive(f);
		} catch {
			this.fail(a, FRAME);
			return;
		}
		if (!bytes) return;
		a.peerProposal = bytes;
		if (a.state === 'laid-out') await this.layoutSteps(a);
	}

	private peerLayoutAck(a: IAttempt, digest: Buffer): void {
		if (!a.layoutSent) {
			this.fail(a, PREMATURE);
			return;
		}
		if (a.peerAck) {
			if (!a.peerAck.equals(digest)) this.fail(a, DISAGREE);
			return;
		}
		a.peerAck = Buffer.from(digest);
		this.compare(a);
	}

	/** Once both agreement digests are present: the fence at I, or the disagreement. */
	private compare(a: IAttempt): void {
		if (!a.agreement || !a.peerAck) return;
		if (!a.agreement.equals(a.peerAck)) this.fail(a, DISAGREE);
		else if (a.initiator) this.abort(a, FENCE);
	}

	/** Section 3's layout steps, once the side holds both proposals; then its layout_ack. */
	private async layoutSteps(a: IAttempt): Promise<void> {
		const host = this.host!;
		const t = a.terms!;
		const s = a.snapshot!;
		const proposals: AssetOpenPair<Buffer> = a.initiator
			? [a.proposal!, a.peerProposal!]
			: [a.peerProposal!, a.proposal!];
		const args = (): [
			IAssetConversionContext,
			AssetOpenPair<Buffer>,
			IAssetConversionBitcoin
		] => [
			this.ctxCopy(a),
			[Buffer.from(proposals[0]), Buffer.from(proposals[1])],
			this.bitcoin(a)
		];
		const described = await this.hostCall(() =>
			host.describeConversion(...args())
		);
		if (!this.still(a, 'laid-out')) return;
		if (!described.ok) {
			this.fail(a, DESCRIBE);
			return;
		}
		const order = this.order(a);
		let layout: IAssetConversionLayout;
		try {
			layout = describedConversionLayout(
				this.layoutBase(a, proposals),
				order(t.contributions).map(BigInt) as [bigint, bigint],
				described.value
			);
			checkConversionLayout(layout, {
				terms: termsCopy(t),
				isInitiator: a.initiator,
				isOpener: s.opener,
				parentValueSats: s.parentValueSats,
				relativeSatoshis: order(t.contributions).map(BigInt) as [bigint, bigint]
			});
		} catch (error) {
			this.fail(a, message(error));
			return;
		}
		await this.barrier(a);
		if (!this.still(a, 'laid-out')) return;
		try {
			const parent = this.preconditions(a.id);
			this.recheck(a, parent);
			if (
				parent.txid !== s.txid ||
				parent.outputIndex !== s.outputIndex ||
				parent.height !== s.height ||
				parent.localBalanceMsat !== s.localBalanceMsat ||
				parent.remoteBalanceMsat !== s.remoteBalanceMsat
			)
				throw new Error(T.parent);
		} catch (error) {
			this.fail(a, message(error));
			return;
		}
		const layoutDigest = assetConversionLayoutDigest(layout);
		const prepared = await this.hostCall(() =>
			host.prepareConversion(...args(), Buffer.from(layoutDigest))
		);
		if (!this.still(a, 'laid-out')) return;
		const plan = prepared.ok
			? (prepared.value as { digest?: unknown } | null | undefined)?.digest
			: undefined;
		if (!Buffer.isBuffer(plan) || plan.length !== 32) {
			this.fail(a, PREPARE);
			return;
		}
		a.layoutDigest = layoutDigest;
		a.planDigest = Buffer.from(plan);
		a.agreement = assetConversionAgreementDigest(layoutDigest, a.planDigest);
		this.sendLayoutAck(a);
		this.compare(a);
	}

	/** The engine's bitcoin facts for the host, fresh copies each call. */
	private bitcoin(a: IAttempt): IAssetConversionBitcoin {
		const t = a.terms!;
		const s = a.snapshot!;
		const order = this.order(a);
		const init = decodeSpliceMessage(a.init!);
		const ack = decodeSpliceAckMessage(a.ack!);
		return {
			fundingKeys: [
				Buffer.from(init.fundingPubkey),
				Buffer.from(ack.fundingPubkey)
			],
			lockTime: init.locktime,
			minimumDepth: t.lockDepth,
			feeratePerKw: t.fees.feeratePerKw,
			parent: {
				type: s.type,
				channelType: s.channelType,
				valueSats: s.parentValueSats,
				fundingKeys: this.parentKeys(a),
				...(s.root !== undefined && { root: Buffer.from(s.root, 'hex') })
			},
			candidate: {
				type: s.type === 'plain' ? 'asset' : 'plain',
				channelType: t.targetType,
				maxAcceptedHtlcs: order(t.candidate.maxAcceptedHtlcs),
				dustLimitSats: order(t.candidate.dustLimitSats).map(BigInt) as [
					bigint,
					bigint
				]
			}
		};
	}

	/** The layout fields the engine fills from the attempt and the terms. */
	private layoutBase(
		a: IAttempt,
		proposals: AssetOpenPair<Buffer>
	): Parameters<typeof describedConversionLayout>[0] {
		const t = a.terms!;
		const s = a.snapshot!;
		const order = this.order(a);
		const pair = (p: { opener: string; acceptor: string }): [bigint, bigint] =>
			order(p).map(BigInt) as [bigint, bigint];
		return {
			attempt: Buffer.from(a.attempt!),
			chainHash: Buffer.from(REGTEST_CHAIN_HASH),
			channelId: this.channelId(a),
			init: Buffer.from(a.init!),
			ack: Buffer.from(a.ack!),
			termsDigest: Buffer.from(a.digest!),
			targetType: Buffer.from(t.targetType, 'hex'),
			direction: t.direction,
			parent: Transaction.fromHex(s.funding.fundingTxHex),
			parentIndex: s.outputIndex,
			parentKeys: this.parentKeys(a),
			parentType: s.type,
			...(s.root !== undefined && { parentRoot: Buffer.from(s.root, 'hex') }),
			...(s.priorDigest !== undefined && {
				priorDigest: Buffer.from(s.priorDigest, 'hex')
			}),
			stateNumber: s.height,
			parentBalancesMsat: a.initiator
				? [s.localBalanceMsat, s.remoteBalanceMsat]
				: [s.remoteBalanceMsat, s.localBalanceMsat],
			feeratePerKw: t.fees.feeratePerKw,
			feeBudgets: pair(t.fees.budgets),
			candidateMaxAcceptedHtlcs: order(t.candidate.maxAcceptedHtlcs),
			candidateDustSats: pair(t.candidate.dustLimitSats),
			firstCommitment: {
				balanceMsat: pair(t.firstCommitment.balanceMsat),
				units: (t.firstCommitment.units ?? []).map((u) => {
					const [initiator, acceptor] = pair(u);
					return { assetId: u.assetId, initiator, acceptor };
				})
			},
			proposalDigests: [sha256(proposals[0]), sha256(proposals[1])]
		};
	}

	/** The parent funding keys, initiator first. */
	private parentKeys(a: IAttempt): [Buffer, Buffer] {
		const f = a.snapshot!.funding;
		const local = Buffer.from(f.localFundingPubkey, 'hex');
		const remote = Buffer.from(f.remoteFundingPubkey, 'hex');
		return a.initiator ? [local, remote] : [remote, local];
	}

	/** A role pair in initiator order. */
	private order(a: IAttempt): <V>(p: { opener: V; acceptor: V }) => [V, V] {
		const openerInitiates = a.initiator === a.snapshot!.opener;
		return <V>(p: { opener: V; acceptor: V }): [V, V] =>
			openerInitiates ? [p.opener, p.acceptor] : [p.acceptor, p.opener];
	}

	/** The await rule: the handler goes on only in the state it started in. */
	private still(a: IAttempt, state: State): boolean {
		return !a.ended && a.state === state;
	}

	private ctxCopy(a: IAttempt): IAssetConversionContext {
		const ctx = a.ctx!;
		return {
			...ctx,
			attempt: Buffer.from(ctx.attempt),
			parent: { ...ctx.parent }
		};
	}

	/** The splice TLV against the live terms: the target type's text, or `mismatch`. */
	private conversionProblem(
		a: IAttempt,
		conversion: { termsDigest: Buffer; targetType: Buffer } | undefined,
		mismatch: string
	): string | undefined {
		if (!conversion) return mismatch;
		if (conversion.targetType.toString('hex') !== a.terms!.targetType)
			return T.target;
		if (!conversion.termsDigest.equals(a.digest!)) return mismatch;
		return undefined;
	}

	// ---- The failure rule and the end ----

	/**
	 * Any failed check, key failure, host refusal, close or exit. Before the
	 * side's own stfu it declines (the acceptor drains after its accept);
	 * from it on, it sends tx_abort.
	 */
	private fail(a: IAttempt, text: string): void {
		if (a.ended) return;
		switch (a.state) {
			case 'starting':
				this.end(a, text);
				return;
			case 'announced':
			case 'assessing':
				this.sendReply(a.peer, a.attempt!, a.digest!, text);
				this.end(a, text);
				return;
			case 'accepted':
				this.sendReply(a.peer, a.attempt!, a.digest!, text);
				a.sent = text;
				this.enter(a, 'draining', () => this.end(a, text));
				return;
			case 'aborting':
			case 'draining':
				return;
			default:
				this.abort(a, text);
		}
	}

	/** Send tx_abort with `text` and wait for the echo. */
	private abort(a: IAttempt, text: string): void {
		if (a.ended || a.state === 'aborting') return;
		this.sendAbort(a, text);
		a.sent = text;
		this.enter(a, 'aborting', () => {
			// No echo: disconnect the peer.
			this.end(a, text);
			this.deps.disconnect(a.peer);
		});
	}

	private enter(
		a: IAttempt,
		state: 'aborting' | 'draining',
		expire: () => void
	): void {
		a.state = state;
		this.clearTimers(a);
		a.phase = this.timer(PHASE_BOUND_MS, () =>
			this.enqueue(a, () => {
				if (a.state === state) expire();
			})
		);
	}

	/** Release the hold, forget the attempt, then tell the host when it verified the terms. */
	private end(a: IAttempt, text: string): void {
		if (a.ended) return;
		a.ended = true;
		a.endText = text;
		a.held = false;
		this.clearTimers(a);
		if (this.attempts.get(a.id) === a) this.attempts.delete(a.id);
		if (a.initiator && a.state === 'announced' && !a.replied && a.attempt)
			this.rememberWithdrawn(a.id, a.peer, a.attempt);
		if (!a.verified || !a.ctx || !this.host) return;
		const host = this.host,
			ctx = this.ctxCopy(a);
		void this.hostCall(() => host.abandonConversion(ctx, text)).then((r) => {
			if (!r.ok && r.error !== undefined)
				this.deps.report(
					a.id,
					'Asset conversion host abandon failed: ' + r.error
				);
		});
	}

	private rememberWithdrawn(id: string, peer: string, attempt: Buffer): void {
		const key = withdrawnKey(id, attempt);
		this.forgetWithdrawn(key);
		this.withdrawn.set(key, {
			peer,
			attempt: Buffer.from(attempt),
			timer: this.timer(REPLY_BOUND_MS, () => this.forgetWithdrawn(key))
		});
	}

	private forgetWithdrawn(key: string): void {
		const w = this.withdrawn.get(key);
		if (!w) return;
		clearTimeout(w.timer);
		this.withdrawn.delete(key);
	}

	// ---- Helpers ----

	private open(id: string, peer: string, initiator: boolean): IAttempt {
		const a: IAttempt = {
			id,
			peer,
			initiator,
			state: initiator ? 'starting' : 'assessing',
			held: initiator,
			verified: false,
			ownStfu: false,
			peerStfu: false,
			layoutSent: false,
			chain: Promise.resolve(),
			ended: false
		};
		this.attempts.set(id, a);
		// The initiator's deadline runs from its start, the acceptor's from its accept.
		if (initiator) this.armDeadline(a);
		return a;
	}

	private armDeadline(a: IAttempt): void {
		a.deadline = this.timer(this.deadlineMs, () =>
			this.enqueue(a, () => {
				if (a.state === 'announced' || a.state === 'starting')
					this.fail(a, WITHDRAWN);
				else this.fail(a, TIMED_OUT);
			})
		);
	}

	private get deadlineMs(): number {
		return this.deps.timeoutMs ?? DEFAULT_DEADLINE_MS;
	}

	private clearTimers(a: IAttempt): void {
		for (const t of [a.deadline, a.reply, a.phase]) if (t) clearTimeout(t);
		a.deadline = a.reply = a.phase = undefined;
	}

	private timer(ms: number, run: () => void): ReturnType<typeof setTimeout> {
		const t = setTimeout(run, ms);
		unref(t);
		return t;
	}

	/** Run the attempt's events one at a time. */
	private enqueue(a: IAttempt, run: () => void | Promise<void>): void {
		a.chain = a.chain
			.then(async () => {
				if (!a.ended) await run();
			})
			.catch((error: unknown) => {
				if (a.ended) return;
				this.deps.report(a.id, message(error));
				this.fail(a, message(error));
			});
	}

	/** Throws the end's text once the attempt ended. */
	private live(a: IAttempt): void {
		if (a.ended) throw new Error(a.endText);
	}

	/** Wait for the final and asset update queues, outside both. */
	private async barrier(a: IAttempt): Promise<void> {
		await this.deps.settled(a.id);
	}

	private negotiated(id: string, peer: string): boolean {
		const local = this.deps.localFeatures();
		const current = this.runtime?.storage.loadFinalChannelType(id);
		if (!local || !current) return false;
		const plain =
			current.type === 'plain' ? current.channelType : PLAIN_TARGET_TYPE_HEX;
		return assetConversionNegotiated(
			local,
			this.deps.remoteFeatures(peer),
			Buffer.from(plain, 'hex')
		);
	}

	/** Section 4's rules: the storage reader's, then the funding depth and the splice transports. */
	private preconditions(id: string): IAssetConversionParent {
		const reader = this.runtime
			? finalBranchReaders(this.runtime.storage)?.assetConversionParent
			: undefined;
		if (!reader)
			throw new Error(
				'Asset conversion requires an original conversion wallet'
			);
		const parent = reader(id);
		if (!this.deps.hasDepth(id))
			throw new Error('Asset conversion requires a confirmed live funding');
		if (this.deps.busy(id))
			throw new Error('Asset conversion requires no pending splice');
		return parent;
	}

	/** The engine's checks of the attempt's terms against the parent now. */
	private recheck(a: IAttempt, parent: IAssetConversionParent): void {
		const failure = assetConversionTermsFailure(
			a.terms!,
			this.expectation(a.id, parent, a.reference),
			Date.now()
		);
		if (failure) throw new Error(failure);
	}

	private expectation(
		id: string,
		parent: IAssetConversionParent,
		reference?: string
	): IAssetConversionExpectation {
		const session = this.runtime!.storage.loadFinalOpeningSession(id)!;
		const { terms } = session;
		const limits = session.updateLimits!;
		const byRole = <V>(local: V, remote: V): { opener: V; acceptor: V } =>
			parent.opener
				? { opener: local, acceptor: remote }
				: { opener: remote, acceptor: local };
		const toAsset = parent.type === 'plain';
		return {
			channelId: id,
			parent: {
				txid: parent.txid,
				outputIndex: parent.outputIndex,
				stateNumber: parent.height.toString()
			},
			direction: toAsset ? 'to-asset' : 'to-plain',
			targetType: toAsset
				? ASSET_SPLICE_RECOVERY_TYPE_HEX
				: PLAIN_TARGET_TYPE_HEX,
			dustLimitSats: byRole(
				String(terms.localDustLimitSatoshis),
				String(terms.remoteDustLimitSatoshis)
			),
			maxAcceptedHtlcs: byRole(
				limits.local.maxAcceptedHtlcs,
				limits.remote.maxAcceptedHtlcs
			),
			commitmentFeeratePerKw: parent.commitmentFeeratePerKw,
			...(reference !== undefined && { reference })
		};
	}

	private context(
		a: IAttempt,
		parent: IAssetConversionParent
	): Omit<IAssetConversionContext, 'attempt'> {
		return {
			channelId: a.id,
			peer: a.peer,
			isInitiator: a.initiator,
			isOpener: parent.opener,
			parent: {
				txid: parent.txid,
				outputIndex: parent.outputIndex,
				stateNumber: parent.height.toString(),
				type: parent.type,
				channelType: parent.channelType
			},
			direction: parent.type === 'plain' ? 'to-asset' : 'to-plain'
		};
	}

	/** Allocate and derive this side's candidate funding key, or fail the attempt. */
	private fundingKey(a: IAttempt): Buffer | undefined {
		const { storage, root } = this.runtime!;
		try {
			const index = storage.allocateFinalChannelKeyIndex(1);
			a.keyIndex = index;
			return deriveChannelKeys(root, 1, index).channelBasepoints.fundingPubkey;
		} catch {
			this.fail(a, KEY_FAILED);
			return undefined;
		}
	}

	private conversion(a: IAttempt): { termsDigest: Buffer; targetType: Buffer } {
		return {
			termsDigest: Buffer.from(a.digest!),
			targetType: Buffer.from(a.terms!.targetType, 'hex')
		};
	}

	private channelId(a: IAttempt): Buffer {
		return Buffer.from(a.id, 'hex');
	}

	private stfu(
		a: IAttempt,
		initiator: boolean
	): { channelId: Buffer; initiator: boolean } {
		return { channelId: this.channelId(a), initiator };
	}

	/** The types the attempt receives in its state. */
	private owns(a: IAttempt, type: number): boolean {
		switch (a.state) {
			case 'announced':
			case 'accepted':
				return type === M.STFU;
			case 'draining':
				return type === M.STFU || type === M.TX_ABORT;
			case 'quiescing':
			case 'init-sent':
			case 'quiesced':
			case 'laid-out':
			case 'aborting':
				return (
					type === M.STFU ||
					type === M.SPLICE ||
					type === M.SPLICE_ACK ||
					type === M.TX_ABORT
				);
			default:
				return false;
		}
	}

	private send(a: IAttempt, type: number, payload: Buffer): void {
		this.deps.send(a.peer, type, payload);
	}

	private sendAbort(a: IAttempt, text: string): void {
		a.abortSent = true;
		this.send(
			a,
			M.TX_ABORT,
			encodeTxAbortMessage({
				channelId: this.channelId(a),
				data: Buffer.from(text, 'utf8')
			})
		);
	}

	private sendTerms(a: IAttempt): void {
		this.sendObject(a, 'conversion_terms', a.bytes!);
	}

	/** The local proposal as this side's layout. */
	private sendLayout(a: IAttempt): void {
		this.sendObject(a, 'layout', a.proposal!);
		a.layoutSent = true;
	}

	private sendLayoutAck(a: IAttempt): void {
		this.sendFrame(a, {
			phase: 'layout_ack',
			attempt: a.attempt!,
			digest: a.agreement!,
			total: 0,
			offset: 0,
			bytes: Buffer.alloc(0)
		});
	}

	private sendObject(
		a: IAttempt,
		phase: 'conversion_terms' | 'layout',
		bytes: Buffer
	): void {
		const digest = sha256(bytes);
		for (let offset = 0; offset < bytes.length; offset += ASSET_OPEN_CHUNK_SIZE)
			this.sendFrame(a, {
				phase,
				attempt: a.attempt!,
				digest,
				total: bytes.length,
				offset,
				bytes: bytes.subarray(offset, offset + ASSET_OPEN_CHUNK_SIZE)
			});
	}

	private sendFrame(a: IAttempt, frame: IAssetOpenFrame): void {
		this.deps.send(
			a.peer,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(
				BeignetCustomSubtype.ASSET_SPLICE,
				encodeAssetOpenFrame(frame)
			)
		);
	}

	/** An accept, or a decline carrying `reason`. */
	private sendReply(
		peer: string,
		attempt: Buffer,
		digest: Buffer,
		reason?: string
	): void {
		let bytes = Buffer.of(0);
		if (reason !== undefined) {
			let text: Buffer;
			try {
				text = encodeBolt1String(reason, 'conversion_reply reason');
			} catch {
				text = Buffer.from(declineReason(Buffer.from(reason, 'utf8')), 'utf8');
			}
			bytes = Buffer.concat([Buffer.of(1), text.subarray(0, REASON_LIMIT)]);
		}
		this.deps.send(
			peer,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(
				BeignetCustomSubtype.ASSET_SPLICE,
				encodeAssetOpenFrame({
					phase: 'conversion_reply',
					attempt,
					digest,
					total: bytes.length,
					offset: 0,
					bytes
				})
			)
		);
	}

	/** A host call, made at once, under the 15 second bound. */
	private async hostCall<V>(
		call: () => V | Promise<V>
	): Promise<{ ok: true; value: V } | { ok: false; error?: string }> {
		let answer: Promise<V>;
		try {
			answer = Promise.resolve(call());
		} catch (error) {
			return { ok: false, error: message(error) };
		}
		let timer: ReturnType<typeof setTimeout> | undefined;
		const bound = new Promise<{ ok: false }>((done) => {
			timer = setTimeout(() => done({ ok: false }), HOST_BOUND_MS);
			unref(timer);
		});
		try {
			return await Promise.race([
				answer.then((value) => ({ ok: true as const, value })),
				bound
			]);
		} catch (error) {
			return { ok: false, error: message(error) };
		} finally {
			if (timer) clearTimeout(timer);
		}
	}
}
