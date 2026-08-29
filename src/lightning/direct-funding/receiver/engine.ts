/**
 * The direct-funding receiver engine (issue #612, LFBW port #532 workstream
 * 4C).
 *
 * A payer offers to spend one of its UTXOs into a funding transaction we
 * negotiate with our liquidity peer, and we come back with a transaction for
 * it to sign. The payer's on-chain payment IS our channel funding, either a
 * new v2 dual-funded channel or a splice into the one we already have.
 *
 * What this engine does not do matters as much as what it does. It never holds
 * the payer's coin and never signs for it. It decides whether to spend a
 * session on the offer, verifies that the coin exists and that the payer
 * controls it, drives the interactive transaction to the point where the bytes
 * are final, attests to those bytes with the node identity key, and hands them
 * over.
 *
 * Two properties everything else is arranged around:
 *
 *  - At-least-once delivery, exactly-once effects. Every response is recorded
 *    per offer id; a duplicate offer with the same content replays the record
 *    and starts nothing, up to and including the receipt. An offer id reused
 *    with different content is refused, never served. The response log is
 *    per-process; what crosses a restart is on the request record itself (the
 *    attempt budget, the busy mark, and the receipt a paid request replays).
 *  - Every failure path releases the concurrency slot, the outpoint
 *    reservation and any channel or splice the session started. The fork left
 *    a live channel behind on three separate failure paths (defect D5). A
 *    funding the channel REFUSES to release is the one exception, and it keeps
 *    the payer's witness obligation open rather than declaring the exchange
 *    over: delivering the witness is the only exit the channel left.
 */

import { EventEmitter } from 'events';
import * as bitcoin from 'bitcoinjs-lib';
import type { ISpliceWalletInput } from '../../channel/channel';
import { BeignetCustomSubtype } from '../../message/custom';
import { zbase32Decode } from '../../crypto/message-signing';
import {
	decodeSealedFrame,
	encodeSealedFrame,
	IDfLaneKeys,
	openFrame,
	sealFrame
} from '../frames';
import {
	attestationMessage,
	decodeDfOffer,
	decodeDfWitness,
	encodeDfOfferAck,
	encodeDfReceipt,
	encodeDfSignRequest,
	IDfOffer,
	IDfPrevout,
	IDfWitness
} from '../messages';
import {
	DF_SIGNATURE_BYTES,
	DirectFundingError,
	IDfRequestRecord
} from '../types';
import type { DfTransportRegistry } from '../transport/registry';
import type { IDfInboundFrame, IDfLaneSender } from '../transport/types';
import {
	contentHashOf,
	DfOfferSessions,
	IDfOfferSession,
	outpointKey
} from './sessions';
import {
	classifyOfferedCoin,
	fundingTransactionProblem,
	offerFieldProblem,
	ownershipProblem
} from './verify';
import {
	DF_DEFAULT_SPLICE_FEERATE_PERKW,
	DF_LOG_OFFER_ACCEPTED,
	DF_LOG_OFFER_COMPLETED,
	DF_LOG_OFFER_DECLINED,
	DF_LOG_OFFER_DROPPED,
	DF_LOG_OFFER_FAILED,
	DF_MAX_INFLIGHT_OFFER_SESSIONS,
	DF_MAX_OFFER_SESSIONS,
	DF_MAX_REQUEST_ATTEMPTS,
	DF_NEGOTIATION_TIMEOUT_MS,
	DF_OFFER_SESSION_TTL_MS,
	DF_OUTPOINT_COOLDOWN_MS,
	DF_RECEIVER_SWEEP_INTERVAL_MS,
	DF_WITNESS_TIMEOUT_MS,
	DfOfferDropReason,
	IDfChannelHandle,
	IDfPendingSpliceTx,
	IDfPendingV2FundingTx,
	IDfReceiverConfig,
	IDfReceiverDeps
} from './types';

/** The negotiated transaction, however it was negotiated. */
interface IDfFinalTx {
	channelId: Buffer;
	tx: bitcoin.Transaction;
	/** Funding txid, DISPLAY byte order, as the receipt carries it. */
	fundingTxidDisplay: Buffer;
	fundingOutputIndex: number;
	prevouts: { scripts: Buffer[]; values: bigint[] };
	owedExternalIndices: number[];
	/**
	 * Value the funding output already had to carry before this payment: a
	 * splice's pre-splice capacity, zero for a new channel. Undefined when a
	 * splice's shared input has no resolvable value, which is not something to
	 * attest around: without it there is no floor to hold the new funding output
	 * to and the whole pre-splice capacity could quietly go missing.
	 */
	baseFundingValueSat?: bigint;
	/** Splice only. */
	sharedInputIndex?: number;
}

type DfFinalTxWaiter = (final: IDfFinalTx) => void;

/**
 * The payer's witnesses as they arrive, buffered.
 *
 * Installed BEFORE the sign request goes out, for the reason the negotiation
 * waiter is installed before the open: on a synchronous lane (one operator
 * running payer and receiver in one process, which rev 2 names as the intended
 * first deployment) the answer comes back inside the send.
 */
class DfWitnessQueue {
	/** Enough for a payer retrying a rejected witness, and no more. */
	private static readonly MAX_BUFFERED = 8;
	private readonly buffered: IDfWitness[] = [];
	private waiter: ((witness: IDfWitness) => void) | null = null;

	constructor(private readonly session: IDfOfferSession) {
		session.onWitness = (witness): void => this.push(witness);
	}

	private push(witness: IDfWitness): void {
		const waiter = this.waiter;
		if (waiter) {
			this.waiter = null;
			waiter(witness);
			return;
		}
		if (this.buffered.length < DfWitnessQueue.MAX_BUFFERED) {
			this.buffered.push(witness);
		}
	}

	next(timeoutMs: number): Promise<IDfWitness> {
		const ready = this.buffered.shift();
		if (ready) return Promise.resolve(ready);
		return new Promise<IDfWitness>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.waiter = null;
				reject(new Error('payer never delivered its witness'));
			}, timeoutMs);
			timer.unref?.();
			this.waiter = (witness): void => {
				clearTimeout(timer);
				resolve(witness);
			};
		});
	}

	close(): void {
		this.waiter = null;
		this.session.onWitness = undefined;
	}
}

/** What one admitted offer carries into the funding stage. */
interface IDfSessionContext {
	offer: IDfOffer;
	session: IDfOfferSession;
	record: IDfRequestRecord;
	prevTx: bitcoin.Transaction;
	confirmed?: boolean;
	liquidityPeer: string;
	/** Authenticated on the lane AND in the operator's trusted set. */
	paired: boolean;
}

type ResolvedConfig = Required<
	Omit<IDfReceiverConfig, 'minAmountSat' | 'maxAmountSat' | 'requiredSequence'>
> &
	Pick<IDfReceiverConfig, 'minAmountSat' | 'maxAmountSat' | 'requiredSequence'>;

export class DirectFundingReceiver extends EventEmitter {
	private readonly state: DfOfferSessions;
	private readonly cfg: ResolvedConfig;
	private readonly v2Waiters = new Map<string, DfFinalTxWaiter>();
	private readonly spliceWaiters = new Map<string, DfFinalTxWaiter>();
	private sweepTimer: NodeJS.Timeout | null = null;
	private detachers: Array<() => void> = [];
	private started = false;

	constructor(
		private readonly deps: IDfReceiverDeps,
		config: IDfReceiverConfig = {}
	) {
		super();
		this.cfg = {
			minAmountSat: config.minAmountSat,
			maxAmountSat: config.maxAmountSat,
			requiredSequence: config.requiredSequence,
			maxInflightSessions:
				config.maxInflightSessions ?? DF_MAX_INFLIGHT_OFFER_SESSIONS,
			maxSessions: config.maxSessions ?? DF_MAX_OFFER_SESSIONS,
			maxRequestAttempts: config.maxRequestAttempts ?? DF_MAX_REQUEST_ATTEMPTS,
			sessionTtlMs: config.sessionTtlMs ?? DF_OFFER_SESSION_TTL_MS,
			outpointCooldownMs: config.outpointCooldownMs ?? DF_OUTPOINT_COOLDOWN_MS,
			negotiationTimeoutMs:
				config.negotiationTimeoutMs ?? DF_NEGOTIATION_TIMEOUT_MS,
			witnessTimeoutMs: config.witnessTimeoutMs ?? DF_WITNESS_TIMEOUT_MS,
			sweepIntervalMs: config.sweepIntervalMs ?? DF_RECEIVER_SWEEP_INTERVAL_MS,
			spliceFeeratePerKw:
				config.spliceFeeratePerKw ?? DF_DEFAULT_SPLICE_FEERATE_PERKW,
			allowSplice: config.allowSplice ?? false
		};
		this.state = new DfOfferSessions(this.cfg.maxSessions);
	}

	// ─────────────── Lifecycle ───────────────

	/**
	 * Arm the sweep and subscribe to the two events that say an interactive
	 * transaction is final and a third-party witness is owed. Both already
	 * carry `externalInputIndices` (issues #554 and #592), so the engine learns
	 * what is outstanding without inspecting channel state, and the sign
	 * request cannot go out before the commitment_signed exchange has completed
	 * because that is exactly when the events fire.
	 */
	start(): void {
		if (this.started) return;
		this.started = true;
		this.detachers.push(
			this.deps.onTxSigsNeeded((e) => {
				if (!e.externalInputIndices?.length) return;
				this.resolveFinalTx(
					this.v2Waiters,
					this.deps.getPendingV2FundingTx(e.channelId),
					e.channelId
				);
			})
		);
		this.detachers.push(
			this.deps.onSpliceTxSigsNeeded((e) => {
				if (!e.externalInputIndices.length) return;
				this.resolveFinalTx(
					this.spliceWaiters,
					this.deps.getPendingSpliceTx(e.channelId),
					e.channelId
				);
			})
		);
		this.sweepTimer = setInterval(
			() => this.state.sweep(this.now()),
			this.cfg.sweepIntervalMs
		);
		this.sweepTimer.unref?.();
	}

	stop(): void {
		this.started = false;
		if (this.sweepTimer) clearInterval(this.sweepTimer);
		this.sweepTimer = null;
		for (const detach of this.detachers) detach();
		this.detachers = [];
		this.v2Waiters.clear();
		this.spliceWaiters.clear();
	}

	/** Route every enabled lane's inbound frames here. Call after start(). */
	async attach(registry: DfTransportRegistry): Promise<() => void> {
		const detach = await registry.attachInbound((frame) =>
			this.handleFrame(frame)
		);
		this.detachers.push(detach);
		return detach;
	}

	/** Live and tombstoned offer records, for tests and diagnostics. */
	sessionCount(): number {
		return this.state.size();
	}

	inflightCount(): number {
		return this.state.inflightCount();
	}

	// ─────────────── Inbound frames ───────────────

	/**
	 * The receiver sink. Two subtypes are ours; the rest belong to the payer
	 * role. Nothing here throws: a lane hands one frame to every listener, and
	 * a throw would cost the others theirs.
	 */
	handleFrame(frame: IDfInboundFrame): void {
		try {
			if (frame.subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				this.onOfferFrame(frame);
			} else if (
				frame.subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS
			) {
				this.onWitnessFrame(frame);
			}
		} catch (err) {
			this.log(DF_LOG_OFFER_DROPPED, {
				reason: 'handler_failed',
				error: errorText(err)
			});
		}
	}

	private onOfferFrame(frame: IDfInboundFrame): void {
		const wire = decodeSealedFrame(frame.payload);
		if (!wire?.requestId || !wire.ephemeralPublicKey) {
			this.drop(DfOfferDropReason.NOT_AN_OPENING_FRAME, frame);
			return;
		}
		// The onion lane resolves the request from the private path_id; a frame
		// that opens under a different one is not the exchange that path was
		// minted for, whatever the seal says.
		if (frame.boundRequestId && !frame.boundRequestId.equals(wire.requestId)) {
			this.drop(DfOfferDropReason.REQUEST_ID_MISMATCH, frame);
			return;
		}
		const lane = this.deps.requests.laneKeysForFrame(wire);
		if (!lane) {
			this.drop(DfOfferDropReason.UNKNOWN_REQUEST, frame);
			return;
		}
		const body = openFrame(
			lane.keys.recvKey,
			wire.requestId,
			frame.subtype,
			wire
		);
		if (!body) {
			this.drop(DfOfferDropReason.NOT_AUTHENTICATED, frame);
			return;
		}
		let offer: IDfOffer;
		try {
			offer = decodeDfOffer(body);
		} catch {
			this.drop(DfOfferDropReason.MALFORMED_MESSAGE, frame);
			return;
		}
		void this.admit(frame, lane.record, lane.keys, offer, body);
	}

	/**
	 * The payer's witness. It is a continuation frame, so it names no request:
	 * only sessions actually waiting for one on this lane are tried, which is
	 * at most the concurrency cap and never the whole session map.
	 */
	private onWitnessFrame(frame: IDfInboundFrame): void {
		const wire = decodeSealedFrame(frame.payload);
		if (!wire) {
			this.drop(DfOfferDropReason.NO_SESSION, frame);
			return;
		}
		for (const session of this.state.witnessWaitersOn(frame.laneKey)) {
			const body = openFrame(
				session.keys.recvKey,
				session.requestId,
				frame.subtype,
				wire
			);
			if (!body) continue;
			let witness: IDfWitness;
			try {
				witness = decodeDfWitness(body);
			} catch {
				this.drop(DfOfferDropReason.MALFORMED_MESSAGE, frame);
				return;
			}
			if (witness.offerId.toString('hex') !== session.offerIdHex) continue;
			session.onWitness?.(witness);
			return;
		}
		this.drop(DfOfferDropReason.NO_SESSION, frame);
	}

	// ─────────────── Admission ───────────────

	/**
	 * Rev 2's admission order, arm by arm, with everything cheap ahead of
	 * everything expensive and the single chain round trip last.
	 *
	 * The steps that read shared state are re-run after that round trip, in one
	 * synchronous block with the reservation and the session insert. Between
	 * the two halves the engine is awaiting, and a burst of offers must not all
	 * pass a cap none of them had taken a slot against yet; the admission guard
	 * bounds how many can sit in that window.
	 */
	private async admit(
		frame: IDfInboundFrame,
		record: IDfRequestRecord,
		keys: IDfLaneKeys,
		offer: IDfOffer,
		offerBytes: Buffer
	): Promise<void> {
		const offerIdHex = offer.offerId.toString('hex');
		const contentHash = contentHashOf(offerBytes);

		// 1. Sweep first: an expired session, reservation or attempt record must
		// never be the reason a fresh offer is refused.
		this.state.sweep(this.now());

		// 2. Duplicate offer id. Same content replays the record verbatim and
		// starts nothing; different content is refused, never served.
		const existing = this.state.get(offerIdHex);
		if (existing) {
			// The id is a hash of the coin and the amount, so two REQUESTS can
			// reach for it. A replay hands back a receipt, so it may only ever
			// answer the request the recorded session was served for; matching
			// content alone would leak one payer's receipt to another.
			if (
				existing.contentHash !== contentHash ||
				existing.receiptHashHex !== record.receiptHash
			) {
				this.declineUnrecorded(
					frame,
					keys,
					record,
					offer,
					'offer id reused with different content'
				);
				return;
			}
			this.replay(existing, frame, keys);
			return;
		}
		// No session, and the request says this very offer already paid it: the
		// exchange ran before a restart, which took the session record with it.
		// The receipt is the one thing the payer still needs and the only thing
		// left that can answer it, so it is replayed from the request itself.
		if (offer.receiptHash.toString('hex') === record.receiptHash) {
			const paid = this.deps.requests.paidOffer(record.receiptHash);
			if (paid?.offerIdHex === offerIdHex) {
				this.replayPaidReceipt(frame, keys, record, offer, paid);
				return;
			}
		}
		if (!this.state.beginAdmission(offerIdHex)) {
			this.drop(DfOfferDropReason.ADMISSION_IN_PROGRESS, frame);
			return;
		}
		try {
			await this.admitGuarded(
				frame,
				record,
				keys,
				offer,
				offerIdHex,
				contentHash
			);
		} catch (err) {
			// Nothing below may escape into the lane's dispatch.
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: offerIdHex,
				error: errorText(err)
			});
		} finally {
			this.state.endAdmission(offerIdHex);
		}
	}

	private async admitGuarded(
		frame: IDfInboundFrame,
		record: IDfRequestRecord,
		keys: IDfLaneKeys,
		offer: IDfOffer,
		offerIdHex: string,
		contentHash: string
	): Promise<void> {
		const decline = (reason: string): void =>
			this.declineUnrecorded(frame, keys, record, offer, reason);

		// 3. Concurrency cap. This offer already counts (it holds an admission
		// guard), so `> max` admits exactly `max` sessions: the fork tested the
		// count AFTER inserting and with the wrong comparison, so its stated 4
		// was really 6 (defect D16).
		if (this.state.inflightCount() > this.cfg.maxInflightSessions) {
			decline('too many concurrent funding sessions');
			return;
		}
		if (this.state.atSessionCeiling()) {
			decline('too many direct funding sessions on record');
			return;
		}

		// 4. A liquidity peer to negotiate the funding with.
		const lsp = this.deps.liquidityPeer();
		if (!lsp) {
			decline('no liquidity peer');
			return;
		}

		// 5. The offer must name the request it sealed to, and that request must
		// still be payable. The frame already proved the payer holds the
		// request's key; this catches an offer paying one request while naming
		// another, and an offer against a receipt already revealed.
		const receiptHashHex = offer.receiptHash.toString('hex');
		if (receiptHashHex !== record.receiptHash) {
			decline('receipt hash does not match the request this offer opened');
			return;
		}
		if (this.deps.requests.isTombstoned(receiptHashHex)) {
			decline('this request has already been paid');
			return;
		}

		// 6. The offer's own fields: identity, amount bounds, sequence, change
		// script. All free, and all of them things the fork checked late or not
		// at all (defects D8, D9, D10).
		const fieldProblem = offerFieldProblem(offer, this.cfg);
		if (fieldProblem) {
			decline(fieldProblem);
			return;
		}

		// 7. One active offer per request. A marker naming THIS offer id and no
		// session to go with it is one a restart left behind: serving it would
		// be a second channel session for one payment, not the replay a live
		// duplicate gets above.
		const attempts = this.deps.requests.attemptsFor(receiptHashHex);
		if (attempts.activeOfferId) {
			decline('request already has an active funding attempt');
			return;
		}

		// 8. Per-request lifetime attempt cap. Out of attempts means a new
		// request has to be minted; nothing about this one comes back.
		if (attempts.attempts >= this.cfg.maxRequestAttempts) {
			decline('too many funding attempts for this request');
			return;
		}

		// 9. The offer names an outpoint; the transaction comes from OUR chain
		// source, so everything below is chain truth rather than a payer claim.
		const txidHex = offer.txid.toString('hex');
		let prevTx: bitcoin.Transaction;
		try {
			prevTx = bitcoin.Transaction.fromBuffer(
				await this.deps.chain.getTransaction(txidHex)
			);
		} catch {
			decline('offered transaction not found on chain');
			return;
		}
		// A backend answering with some other transaction would otherwise have
		// us reserve, verify and fund against an outpoint nobody named.
		if (prevTx.getId() !== txidHex) {
			decline('offered transaction not found on chain');
			return;
		}

		// 10. The named output, at the value the offer claims for it.
		const out = prevTx.outs[offer.vout];
		if (!out || BigInt(out.value) !== offer.valueSat) {
			decline('offer value does not match the transaction output it names');
			return;
		}
		const script = Buffer.from(out.script);
		const coin = await classifyOfferedCoin(this.deps.chain, {
			txidDisplayHex: txidHex,
			vout: offer.vout,
			script
		});
		if (coin.spent) {
			// Cheap, and without it a spent coin burns a capped slot until its
			// session times out (defect D12).
			decline('offered coin is already spent');
			return;
		}

		// 11. The payer controls the coin.
		const ownership = ownershipProblem(offer, script);
		if (ownership) {
			decline(ownership);
			return;
		}

		// ── Everything from here mutates shared state, synchronously. ──

		// Re-read what a concurrent admission could have changed while this one
		// was awaiting the chain.
		if (this.deps.requests.isTombstoned(receiptHashHex)) {
			decline('this request has already been paid');
			return;
		}
		if (
			this.state.get(offerIdHex) ||
			this.state.atSessionCeiling() ||
			this.state.inflightCount() > this.cfg.maxInflightSessions
		) {
			decline('too many concurrent funding sessions');
			return;
		}
		const current = this.deps.requests.attemptsFor(receiptHashHex);
		if (
			current.activeOfferId ||
			current.attempts >= this.cfg.maxRequestAttempts
		) {
			decline('request already has an active funding attempt');
			return;
		}

		// 12. One outpoint funds at most one in-flight session. A duplicate
		// offer never reaches here, so a conflicting reservation is a DIFFERENT
		// offer wanting the same coin.
		const outpoint = outpointKey(txidHex, offer.vout);
		const reserved = this.state.reservationFor(outpoint);
		if (reserved && reserved.offerIdHex !== offerIdHex) {
			decline('input already committed to another offer');
			return;
		}
		const now = this.now();
		this.state.reserve(outpoint, offerIdHex, now + this.cfg.sessionTtlMs);

		const session: IDfOfferSession = {
			offerIdHex,
			contentHash,
			receiptHashHex,
			outpoint,
			requestId: Buffer.from(record.requestId, 'hex'),
			keys,
			laneKey: frame.laneKey,
			reply: frame.reply,
			responses: [],
			inflight: true,
			terminal: false,
			committed: false,
			slotExpiresAt: now + this.cfg.sessionTtlMs,
			// The record outlives the slot by the request's own life, so a payer
			// that can still pay can still be replayed.
			expiresAt: Math.max(now + this.cfg.sessionTtlMs, record.expiresAt)
		};
		this.state.open(session);
		// Charged on the REQUEST rather than in this map: the count is a
		// per-request lifetime budget and the marker is what stops a duplicate
		// arriving after a restart from starting a second channel session, and
		// neither can do its job from memory alone.
		this.deps.requests.beginAttempt(
			receiptHashHex,
			offerIdHex,
			session.slotExpiresAt
		);
		// The slot is the session's from here, so the admission guard hands it
		// over rather than counting a second time for the whole exchange.
		this.state.endAdmission(offerIdHex);

		const paired =
			frame.authenticatedPeer !== undefined &&
			this.deps.isTrustedPayer(frame.authenticatedPeer);
		this.log(DF_LOG_OFFER_ACCEPTED, {
			offerId: offerIdHex,
			amountSat: offer.amountSat.toString(),
			paired
		});
		this.emit('offer:accepted', { offerId: offerIdHex, paired });

		await this.serve({
			offer,
			session,
			record,
			prevTx,
			confirmed: coin.confirmed,
			liquidityPeer: lsp,
			paired
		});
	}

	// ─────────────── Serving an admitted offer ───────────────

	/**
	 * Drive the funding, then hand over the receipt. Every exit releases the
	 * concurrency slot, the outpoint reservation and the request's active-offer
	 * mark; a failure additionally unwinds whatever channel work had started,
	 * and keeps the witness obligation open when that unwind is refused.
	 */
	private async serve(ctx: IDfSessionContext): Promise<void> {
		let unwind: (() => boolean) | null = null;
		let witnesses: DfWitnessQueue | null = null;
		let stillOwed: (() => void) | null = null;
		try {
			this.send(
				ctx.session.reply,
				ctx.session,
				BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
				encodeDfOfferAck({ offerId: ctx.offer.offerId, accepted: true })
			);
			const input = this.externalInputFor(ctx);
			const spliceChannel = this.spliceTarget(ctx);
			const isSplice = spliceChannel !== null;
			const started = spliceChannel
				? this.startSplice(ctx, spliceChannel, input)
				: this.startOpen(ctx, input);
			unwind = started.unwind;
			const final = await started.final;
			// The channel id the event carried is authoritative: a v2 open answers
			// to its temporary id until accept_channel2 and to its permanent one
			// afterwards, and an unwind has to name whichever is current.
			unwind = (): boolean =>
				this.unwindFunding(isSplice, final.channelId, ctx);
			witnesses = new DfWitnessQueue(ctx.session);
			this.sendSignRequest(ctx, final);
			stillOwed = (): void => this.keepWitnessObligation(ctx, final, isSplice);
			await this.collectWitness(ctx, final, isSplice, witnesses);
			// The witness reached the channel: our tx_signatures are out and
			// there is nothing left that could be unwound.
			unwind = null;
			stillOwed = null;
			this.sendReceipt(ctx, final);
			this.finish(ctx, true);
		} catch (err) {
			// A refused unwind means the channel is past the point where our word
			// alone could take the funding back, and delivering the witness is the
			// only exit it leaves (Channel.provideSpliceExternalWitness says so
			// outright). The obligation therefore outlives the session's own
			// deadlines, up to the request's.
			const released = unwind ? unwind() : true;
			witnesses?.close();
			witnesses = null;
			this.fail(ctx, errorText(err), released ? null : stillOwed);
		} finally {
			witnesses?.close();
		}
	}

	/**
	 * Our "wallet input" IS the payer's. It is contributed and emitted on the
	 * wire like any of ours, its signWitness is never called, and our
	 * tx_signatures is withheld until its slot is filled (issue #554).
	 */
	private externalInputFor(ctx: IDfSessionContext): ISpliceWalletInput {
		return {
			prevTx: ctx.prevTx.toBuffer(),
			prevOutputIndex: ctx.offer.vout,
			value: ctx.offer.valueSat,
			sequence: ctx.offer.sequence,
			external: true,
			// Set from what the chain actually says, and omitted when it said
			// nothing conclusive: the fork asserted true unconditionally (defect
			// D13), which would satisfy a peer's require_confirmed_inputs over a
			// coin still in the mempool.
			...(ctx.confirmed !== undefined ? { confirmed: ctx.confirmed } : {}),
			signWitness: (): Buffer[] => {
				throw new Error('external input: the witness comes from the payer');
			}
		};
	}

	/**
	 * Splice the channel we already have, or open a new one.
	 *
	 * The splice path needs an authenticated AND paired payer: it puts a
	 * third party's unconfirmed coin under an existing channel's funding, where
	 * a double spend takes the whole channel with it rather than just this
	 * payment. Rev 2 classes splice-in as an extension, so it is additionally
	 * off unless the operator asked for it.
	 */
	private spliceTarget(ctx: IDfSessionContext): Buffer | null {
		if (!this.cfg.allowSplice || !ctx.paired) return null;
		return this.deps.usableChannelWith(ctx.liquidityPeer);
	}

	private startOpen(
		ctx: IDfSessionContext,
		input: ISpliceWalletInput
	): { final: Promise<IDfFinalTx>; unwind: () => boolean } {
		// Registered BEFORE the open: a fully synchronous transport runs the
		// whole negotiation inside openChannelV2, and a waiter installed after
		// it would already have missed the event.
		const final = this.awaitFinalTx(
			this.v2Waiters,
			ctx.session.outpoint,
			this.cfg.negotiationTimeoutMs
		);
		let handle: IDfChannelHandle;
		try {
			handle = this.deps.openChannelV2(ctx.liquidityPeer, {
				fundingSatoshis: ctx.offer.amountSat,
				contribution: {
					inputs: [input],
					changeScript: ctx.offer.changeScript
				},
				// Zero-conf only for an authenticated, paired payer, on top of
				// upstream's own two factors (canOpenZeroConfTo and a negotiated
				// option_zeroconf). An anonymous payer's coin can be double spent
				// before it confirms, and that risk belongs to the funder; here
				// the funder is the payer, not the trusted liquidity peer.
				...(ctx.paired && this.deps.canOpenZeroConfTo(ctx.liquidityPeer)
					? { trusted: true }
					: {})
			});
		} catch (err) {
			this.v2Waiters.delete(ctx.session.outpoint);
			void final.catch(() => undefined);
			throw err;
		}
		return {
			final,
			unwind: (): boolean => this.unwindFunding(false, handle.channelId(), ctx)
		};
	}

	private startSplice(
		ctx: IDfSessionContext,
		channelId: Buffer,
		input: ISpliceWalletInput
	): { final: Promise<IDfFinalTx>; unwind: () => boolean } {
		const final = this.awaitFinalTx(
			this.spliceWaiters,
			ctx.session.outpoint,
			this.cfg.negotiationTimeoutMs
		);
		const unwind = (): boolean => this.unwindFunding(true, channelId, ctx);
		let result: { ok: boolean; error?: string };
		try {
			// Synchronous, and it pre-refuses an external input whose output type
			// no witness we could later verify would spend. Let it do that work.
			result = this.deps.spliceInWithInputs(
				channelId,
				ctx.offer.amountSat,
				[input],
				ctx.offer.changeScript,
				this.cfg.spliceFeeratePerKw
			);
		} catch (err) {
			this.spliceWaiters.delete(ctx.session.outpoint);
			void final.catch(() => undefined);
			throw err;
		}
		if (!result.ok) {
			this.spliceWaiters.delete(ctx.session.outpoint);
			void final.catch(() => undefined);
			throw new Error(`splice initiation failed: ${result.error}`);
		}
		return { final, unwind };
	}

	/**
	 * The sign request, and the attestation that makes it worth anything: this
	 * node's identity key binding the payment request to exactly this output in
	 * exactly this transaction. The transaction is hashed rather than embedded
	 * so the signed string stays fixed size; the payer recomputes the hash from
	 * the bytes it was handed.
	 */
	private sendSignRequest(ctx: IDfSessionContext, final: IDfFinalTx): void {
		if (final.baseFundingValueSat === undefined) {
			throw new Error(
				'the shared input value is unresolvable, so the new funding output has no floor'
			);
		}
		const problem = fundingTransactionProblem({
			tx: final.tx,
			fundingOutputIndex: final.fundingOutputIndex,
			minFundingValueSat: final.baseFundingValueSat + ctx.offer.amountSat,
			payerPrevTxid: ctx.prevTx.getHash(),
			payerVout: ctx.offer.vout,
			owedExternalIndices: final.owedExternalIndices,
			offer: ctx.offer
		});
		if (problem) throw new Error(`refusing to attest: ${problem}`);
		const pubkeys = this.deps.fundingPubkeys(final.channelId);
		if (!pubkeys) throw new Error('funding pubkeys are unavailable');
		const rawTx = final.tx.toBuffer();
		const signature = zbase32Decode(
			this.deps.signMessage(
				attestationMessage(
					ctx.offer.offerId,
					rawTx,
					final.fundingOutputIndex,
					pubkeys.local
				)
			)
		);
		if (!signature || signature.length !== DF_SIGNATURE_BYTES) {
			throw new Error('node signer did not return a 65-byte signature');
		}
		const prevouts: IDfPrevout[] = final.prevouts.scripts.map((s, i) => ({
			script: Buffer.from(s),
			valueSat: final.prevouts.values[i]
		}));
		this.send(
			ctx.session.reply,
			ctx.session,
			BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
			encodeDfSignRequest({
				offerId: ctx.offer.offerId,
				rawTx,
				prevouts,
				attestation: {
					fundingOutputIndex: final.fundingOutputIndex,
					localFundingPubkey: pubkeys.local,
					remoteFundingPubkey: pubkeys.remote,
					signature
				},
				...(final.sharedInputIndex !== undefined
					? { sharedInputIndex: final.sharedInputIndex }
					: {})
			})
		);
	}

	/**
	 * Wait for the payer's witness and deliver it to the channel. A refused
	 * delivery leaves channel state untouched and is retryable, so a bad
	 * witness costs the payer another try inside the same deadline rather than
	 * costing it the session.
	 */
	private async collectWitness(
		ctx: IDfSessionContext,
		final: IDfFinalTx,
		isSplice: boolean,
		witnesses: DfWitnessQueue
	): Promise<void> {
		const deadline = this.now() + this.cfg.witnessTimeoutMs;
		const prevTxid = ctx.prevTx.getHash();
		let lastError = 'payer never delivered its witness';
		for (;;) {
			const remaining = deadline - this.now();
			if (remaining <= 0) throw new Error(lastError);
			const witness = await witnesses.next(remaining);
			const result = this.deliverWitness(
				ctx,
				final,
				isSplice,
				prevTxid,
				witness.witness
			);
			if (result.ok) {
				ctx.session.committed = true;
				return;
			}
			if (result.withheld) {
				// The channel took the witness and could not dispatch what it
				// released: the batch's persist failed, and only a reconnect
				// retries it. Nothing here may reveal the receipt for signatures
				// that have not left, and a retry of the same witness cannot help,
				// so the session fails and keeps the obligation open.
				throw new Error(`payer witness accepted but ${result.error}`);
			}
			lastError = `payer witness rejected: ${result.error}`;
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: ctx.session.offerIdHex,
				error: lastError
			});
		}
	}

	/**
	 * One delivery to the channel. `withheld` is the case the boolean cannot
	 * carry: the channel accepted the witness and released our tx_signatures,
	 * and the dispatch that would have sent them was blocked by a failed
	 * persist. The obligation is not discharged by that, so it is never mistaken
	 * for one that is.
	 */
	private deliverWitness(
		ctx: IDfSessionContext,
		final: IDfFinalTx,
		isSplice: boolean,
		prevTxid: Buffer,
		witness: Buffer[]
	): { ok: boolean; withheld?: boolean; error?: string } {
		const result = isSplice
			? this.deps.provideSpliceExternalWitness(
					final.channelId,
					prevTxid,
					ctx.offer.vout,
					witness
			  )
			: this.deps.provideV2ExternalWitness(
					final.channelId,
					prevTxid,
					ctx.offer.vout,
					witness
			  );
		if (result.ok && result.sendsWithheld) {
			return {
				ok: false,
				withheld: true,
				error: 'the channel could not dispatch its tx_signatures'
			};
		}
		return result;
	}

	/**
	 * Keep taking the payer's witness after the session itself has failed.
	 *
	 * Installed only when the funding could not be released: the channel is
	 * then past the point where an abort could take it back, so the payment
	 * either completes or the channel stays wedged, and only the payer's
	 * witness decides which. The handler outlives every session deadline and
	 * goes when the record does, which is bound to the request's own life.
	 */
	private keepWitnessObligation(
		ctx: IDfSessionContext,
		final: IDfFinalTx,
		isSplice: boolean
	): void {
		const { session } = ctx;
		const prevTxid = ctx.prevTx.getHash();
		session.onWitness = (witness): void => {
			const result = this.deliverWitness(
				ctx,
				final,
				isSplice,
				prevTxid,
				witness.witness
			);
			if (!result.ok) {
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: session.offerIdHex,
					error: `late witness rejected: ${result.error}`
				});
				return;
			}
			session.onWitness = undefined;
			session.committed = true;
			try {
				this.sendReceipt(ctx, final);
			} catch (err) {
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: session.offerIdHex,
					error: `late receipt failed: ${errorText(err)}`
				});
				return;
			}
			this.log(DF_LOG_OFFER_COMPLETED, { offerId: session.offerIdHex });
			this.emit('offer:completed', { offerId: session.offerIdHex });
		};
	}

	private sendReceipt(ctx: IDfSessionContext, final: IDfFinalTx): void {
		// From the admitted request record, not a fresh lookup: the request can
		// expire while its funding is in flight, and reloading here would spend
		// the payer's coin and then find the secret that acknowledges it gone.
		const preimage = ctx.record.preimageHex;
		if (!preimage) throw new Error('receipt preimage is no longer available');
		// Tombstone BEFORE the receipt leaves: a request that comes back looking
		// unpaid after a restart is a paid request nothing can recognise. The
		// same write records what paid it, which is what a restart replays.
		try {
			this.deps.requests.markReceiptRevealed(ctx.session.receiptHashHex, {
				offerIdHex: ctx.session.offerIdHex,
				fundingTxidHex: final.fundingTxidDisplay.toString('hex')
			});
		} catch (err) {
			// Only the write failed; the in-memory tombstone stands. Withholding
			// the receipt over it would leave a payer whose coin is already
			// committed with no proof of what it bought, which is the worse of
			// the two failures by a distance.
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: ctx.session.offerIdHex,
				error: `receipt tombstone not persisted: ${errorText(err)}`
			});
		}
		// The complete transaction, when every witness is in: no chain round
		// trip, and a payer holding it can rebroadcast alone. Omitted while the
		// channel counterparty's own tx_signatures are still outstanding.
		const complete = final.tx.ins.every((i) => i.witness.length > 0);
		this.send(
			ctx.session.reply,
			ctx.session,
			BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
			encodeDfReceipt({
				offerId: ctx.offer.offerId,
				preimage: Buffer.from(preimage, 'hex'),
				fundingTxid: final.fundingTxidDisplay,
				...(complete ? { rawTx: final.tx.toBuffer() } : {})
			})
		);
	}

	// ─────────────── Terminal outcomes ───────────────

	private finish(ctx: IDfSessionContext, ok: boolean): void {
		const { session } = ctx;
		session.inflight = false;
		session.terminal = true;
		session.onWitness = undefined;
		this.v2Waiters.delete(session.outpoint);
		this.spliceWaiters.delete(session.outpoint);
		this.deps.requests.endAttempt(session.receiptHashHex, session.offerIdHex);
		// A success releases the coin outright (it is spent); a failure holds it
		// as a cooldown, so the same coin cannot immediately burn another
		// session under a fresh offer id.
		this.state.release(
			session.outpoint,
			session.offerIdHex,
			ok ? undefined : this.now() + this.cfg.outpointCooldownMs
		);
		// The record's own expiry was bound to the request's at admission, so a
		// terminal session keeps answering for as long as the request can still
		// be paid: that is what a payer whose receipt frame was lost replays
		// against.
		if (ok) {
			this.log(DF_LOG_OFFER_COMPLETED, { offerId: session.offerIdHex });
			this.emit('offer:completed', { offerId: session.offerIdHex });
		}
	}

	/**
	 * Fail a session that had already been admitted. The response log is
	 * replaced with a terminal decline, so a duplicate offer is answered "this
	 * is over" rather than replayed a sign request for a transaction that will
	 * never be broadcast. A session whose witness already reached the channel
	 * is NOT declinable: the funding belongs to the network, and what its
	 * record still owes the payer is a receipt.
	 *
	 * `stillOwed` says the same thing about a funding that could not be
	 * released: the transaction can still complete, so declining it would be a
	 * lie, and the witness obligation it installs is the only exit the channel
	 * left open.
	 */
	private fail(
		ctx: IDfSessionContext,
		reason: string,
		stillOwed: (() => void) | null
	): void {
		const { session } = ctx;
		if (!session.committed && !stillOwed) {
			session.responses = [];
			this.send(
				session.reply,
				session,
				BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
				encodeDfOfferAck({
					offerId: ctx.offer.offerId,
					accepted: false,
					reason
				})
			);
		}
		this.finish(ctx, false);
		// After finish(), which clears the callback every settled session drops.
		stillOwed?.();
		this.log(DF_LOG_OFFER_FAILED, {
			offerId: session.offerIdHex,
			error: reason
		});
		this.emit('offer:failed', { offerId: session.offerIdHex, reason });
	}

	/**
	 * Release the peer's half of a funding this session started, and report
	 * whether it went. A refusal is not an error: it means the operation is past
	 * the point where it could be unwound (our tx_signatures left, or the
	 * transaction is fully signed), so the channel owes the network a broadcast
	 * rather than the peer an abort. It is not something to swallow either, and
	 * the caller keeps the witness obligation open on the strength of it.
	 *
	 * Nothing is released back to the funding provider here, unlike the fork's
	 * abort path: a registered contribution bypasses wallet selection outright,
	 * so a direct-funded open or splice never pledges a coin of ours.
	 */
	private unwindFunding(
		isSplice: boolean,
		channelId: Buffer,
		ctx: IDfSessionContext
	): boolean {
		try {
			const result = isSplice
				? this.deps.abortSplice(channelId, 'direct funding session failed')
				: this.deps.abortDualFundedOpen(
						channelId,
						'direct funding session failed'
				  );
			if (!result.ok) {
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: ctx.session.offerIdHex,
					error: `unwind refused: ${result.error}`
				});
			}
			return result.ok;
		} catch (err) {
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: ctx.session.offerIdHex,
				error: `unwind threw: ${errorText(err)}`
			});
			return false;
		}
	}

	// ─────────────── Waiting for the negotiated transaction ───────────────

	private awaitFinalTx(
		waiters: Map<string, DfFinalTxWaiter>,
		key: string,
		timeoutMs: number
	): Promise<IDfFinalTx> {
		return new Promise<IDfFinalTx>((resolve, reject) => {
			const timer = setTimeout(() => {
				waiters.delete(key);
				reject(new Error('funding negotiation did not complete in time'));
			}, timeoutMs);
			timer.unref?.();
			waiters.set(key, (final) => {
				clearTimeout(timer);
				waiters.delete(key);
				resolve(final);
			});
		});
	}

	/**
	 * A channel says an interactive transaction is final and a third party owes
	 * it a witness. The outpoint identifies whose session that is: one outpoint
	 * funds at most one in-flight session, so no channel-id tracking is needed
	 * and a temporary id promoted mid-negotiation cannot lose it.
	 */
	private resolveFinalTx(
		waiters: Map<string, DfFinalTxWaiter>,
		pending: IDfPendingV2FundingTx | IDfPendingSpliceTx | null,
		channelId: Buffer
	): void {
		if (!pending?.prevouts) return;
		const prevouts = pending.prevouts;
		for (const owed of pending.owedExternalInputs) {
			const key = outpointKey(
				Buffer.from(owed.prevTxid).reverse().toString('hex'),
				owed.prevOutputIndex
			);
			const waiter = waiters.get(key);
			if (!waiter) continue;
			const common = {
				channelId: Buffer.from(channelId),
				tx: pending.tx,
				prevouts,
				owedExternalIndices: pending.owedExternalInputs.map((o) => o.inputIndex)
			};
			if ('sharedInputIndex' in pending) {
				waiter({
					...common,
					fundingTxidDisplay: displayTxid(pending.spliceTxid),
					fundingOutputIndex: pending.newFundingOutputIndex,
					// The new funding output carries the pre-splice capacity as
					// well, and the shared input's value IS that capacity.
					baseFundingValueSat: prevouts.values[pending.sharedInputIndex],
					sharedInputIndex: pending.sharedInputIndex
				});
			} else {
				waiter({
					...common,
					fundingTxidDisplay: displayTxid(pending.fundingTxid),
					fundingOutputIndex: pending.fundingOutputIndex,
					baseFundingValueSat: 0n
				});
			}
			return;
		}
	}

	// ─────────────── Frames out ───────────────

	/**
	 * Seal and send one message, recording the PLAINTEXT body against the
	 * session. A replay re-seals: every seal takes a fresh nonce, and reusing
	 * one would put two plaintexts under the same key and nonce. "Byte-identical
	 * responses" is therefore a promise about the message, not the ciphertext,
	 * which is the only form of it a sealed protocol can keep.
	 */
	private send(
		reply: IDfLaneSender,
		session: IDfOfferSession,
		subtype: number,
		body: Buffer
	): void {
		this.state.record(session, subtype, body);
		this.emitSealed(reply, session.keys, session.requestId, subtype, body);
	}

	private emitSealed(
		reply: IDfLaneSender,
		keys: IDfLaneKeys,
		requestId: Buffer,
		subtype: number,
		body: Buffer
	): void {
		const sealed = sealFrame(keys.sendKey, requestId, subtype, body);
		reply.trySend(subtype, encodeSealedFrame(sealed));
	}

	/**
	 * Replay a session's recorded responses on the lane the duplicate arrived
	 * on, and rebind the session to it. A payer whose answer was lost may well
	 * come back over a different transport, and rebinding is the only way it
	 * can be served: nothing is re-run and no second channel session begins.
	 */
	private replay(
		session: IDfOfferSession,
		frame: IDfInboundFrame,
		keys: IDfLaneKeys
	): void {
		session.keys = keys;
		session.laneKey = frame.laneKey;
		session.reply = frame.reply;
		for (const response of session.responses) {
			this.emitSealed(
				frame.reply,
				keys,
				session.requestId,
				response.subtype,
				response.body
			);
		}
	}

	/**
	 * Answer a re-sent offer whose exchange completed before a restart. The
	 * session record is gone with the process, so the receipt is rebuilt from
	 * the request's own durable mark rather than replayed from a response log;
	 * the complete transaction is not part of it, which the receipt's rawTx
	 * field is already optional for.
	 */
	private replayPaidReceipt(
		frame: IDfInboundFrame,
		keys: IDfLaneKeys,
		record: IDfRequestRecord,
		offer: IDfOffer,
		paid: { offerIdHex: string; fundingTxidHex: string }
	): void {
		this.emitSealed(
			frame.reply,
			keys,
			Buffer.from(record.requestId, 'hex'),
			BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
			encodeDfReceipt({
				offerId: offer.offerId,
				preimage: Buffer.from(record.preimageHex, 'hex'),
				fundingTxid: Buffer.from(paid.fundingTxidHex, 'hex')
			})
		);
	}

	/**
	 * A decline that creates no session, so a corrected offer over the same
	 * coin and amount is judged fresh rather than answered from a stale
	 * refusal. Only sessions that reached the funding stage are kept, and it is
	 * those an id reused with different content is refused against.
	 */
	private declineUnrecorded(
		frame: IDfInboundFrame,
		keys: IDfLaneKeys,
		record: IDfRequestRecord,
		offer: IDfOffer,
		reason: string
	): void {
		const offerId = offer.offerId.toString('hex');
		this.log(DF_LOG_OFFER_DECLINED, { offerId, reason });
		this.emit('offer:declined', { offerId, reason });
		this.emitSealed(
			frame.reply,
			keys,
			Buffer.from(record.requestId, 'hex'),
			BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
			encodeDfOfferAck({ offerId: offer.offerId, accepted: false, reason })
		);
	}

	// ─────────────── Odds and ends ───────────────

	private now(): number {
		return this.deps.now ? this.deps.now() : Date.now();
	}

	private drop(reason: DfOfferDropReason, frame: IDfInboundFrame): void {
		this.log(DF_LOG_OFFER_DROPPED, {
			reason,
			transport: frame.type,
			subtype: frame.subtype
		});
	}

	private log(action: string, data: Record<string, unknown>): void {
		try {
			this.deps.log?.(action, data);
		} catch {
			// A throwing log observer must not abandon a funding session.
		}
	}
}

/** Internal byte order in, display byte order out. */
function displayTxid(internal: Buffer): Buffer {
	return Buffer.from(internal).reverse();
}

function errorText(err: unknown): string {
	if (err instanceof DirectFundingError) return `${err.code}: ${err.message}`;
	return err instanceof Error ? err.message : String(err);
}
