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
 *    attempt budget, the busy mark, the funding that mark left in flight, and
 *    the receipt a paid request replays). A re-sent offer whose funding is
 *    still owed a witness is served FROM that funding, never by opening a
 *    second one, and the witness itself is taken from that funding too, on the
 *    lane it names, so a payer that sends one once is still paid (issue #635).
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
	IDfWireFrame,
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
	IDfAttemptFunding,
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

/** What a funding given up with its request is aborted with (issue #644). */
const DF_LAPSED_ABORT_REASON = 'the direct funding request expired';

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

interface DfFinalTxWaiter {
	final: Promise<IDfFinalTx>;
	resolve(final: IDfFinalTx): void;
	cancel(): void;
}

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
	/**
	 * The offered coin's txid in INTERNAL byte order. The whole transaction is
	 * only needed to CONTRIBUTE the input, so a session resuming a funding an
	 * earlier life negotiated never fetches it.
	 */
	prevTxid: Buffer;
	/** Authenticated on the lane AND in the operator's trusted set. */
	paired: boolean;
}

/** A funding under way, however it got there. */
interface IDfStartedFunding {
	final: Promise<IDfFinalTx>;
	unwind: () => boolean;
	isSplice: boolean;
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
			allowSplice: config.allowSplice ?? false,
			allowZeroConf: config.allowZeroConf ?? false
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
		this.restoreFundingHolds();
		this.retireLapsedFundings();
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
		this.sweepTimer = setInterval(() => {
			this.state.sweep(this.now());
			this.retireLapsedFundings();
		}, this.cfg.sweepIntervalMs);
		this.sweepTimer.unref?.();
	}

	/**
	 * Re-take the outpoint reservation of every funding a previous life left in
	 * flight (issue #635).
	 *
	 * The reservations are memory only, and the request's own busy mark stops a
	 * second offer against the SAME request; this is what stops the payer's coin
	 * being pledged to a second one. It runs before the lanes are attached, so
	 * no offer can be judged against an empty reservation table.
	 */
	private restoreFundingHolds(): void {
		for (const held of this.deps.requests.activeFundings()) {
			this.state.reserve(
				held.funding.outpoint,
				held.offerIdHex,
				held.receiptHash,
				held.expiresAt
			);
		}
	}

	/**
	 * Give a funding up once its hold has run out on a request that has itself
	 * expired (issue #644).
	 *
	 * The store keeps that row rather than sweeping it, because the lane key and
	 * the preimage it carries are the only ones that could still answer the
	 * payer; what it cannot do is decide the funding is over. Nothing else
	 * retires the channel either, so it sits pending with the payer's input
	 * unwitnessed until the abort goes out here. The payer's coin is untouched by
	 * any of it: the transaction was never broadcast, so a request it can no
	 * longer be paid against costs it nothing but the wait.
	 *
	 * Only an abort the channel actually completed clears the mark, the same read
	 * `unwindFunding` applies: a v2 tx_abort awaiting its echo has released
	 * nothing (a disconnect forgets it and resumes the negotiation), and a
	 * refusal means the funding is past unwinding and can still complete. Either
	 * way the hold stands, the coin stays reserved with it, and the next tick
	 * tries again, because clearing on one of those answers strands the very
	 * channel this exists to retire.
	 */
	private retireLapsedFundings(): void {
		for (const held of this.deps.requests.lapsedFundings()) {
			// Something is still parked on this outpoint's owed-witness event: a
			// late witness or a re-sent offer that could yet complete the funding,
			// and its own timeout ends the wait soon enough.
			if (
				this.v2Waiters.has(held.funding.outpoint) ||
				this.spliceWaiters.has(held.funding.outpoint)
			) {
				continue;
			}
			const channelId = Buffer.from(held.funding.channelId, 'hex');
			let released = false;
			let outcome: string;
			try {
				const result: { ok: boolean; error?: string; pending?: boolean } = held
					.funding.splice
					? this.deps.abortSplice(channelId, DF_LAPSED_ABORT_REASON)
					: this.deps.abortDualFundedOpen(channelId, DF_LAPSED_ABORT_REASON);
				released = result.ok && result.pending !== true;
				if (released) outcome = 'the pending funding was aborted';
				else if (result.ok) outcome = 'its tx_abort is awaiting the peer echo';
				else if (this.deps.fundingPubkeys(channelId) === null) {
					// A refusal from a channel the node no longer holds at all says
					// the funding is gone, not that it is past unwinding: the echo of
					// our own tx_abort forgets the open, and this is the retry that
					// followed it. Holding the mark on that answer would keep the row
					// and the coin for the rest of the process's life, with nothing
					// left for either to protect.
					released = true;
					outcome = 'the pending funding was already gone';
				} else outcome = `the abort was refused: ${result.error}`;
			} catch (err) {
				outcome = `the abort threw: ${errorText(err)}`;
			}
			if (!released) {
				// The coin stays committed for as long as the funding does. Its
				// reservation lapsed with the funding's hold, and a restart takes none
				// for a funding already lapsed, so re-taking it here is what keeps the
				// same coin out of a second channel: the busy mark guards one request,
				// and a fresh request is not covered by it.
				this.state.reserve(
					held.funding.outpoint,
					held.offerIdHex,
					held.receiptHash,
					this.now() + this.cfg.sessionTtlMs
				);
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: held.offerIdHex,
					channelId: held.funding.channelId,
					error: `${DF_LAPSED_ABORT_REASON}, and the funding is still live: ${outcome}`
				});
				continue;
			}
			this.state.release(held.funding.outpoint, held.offerIdHex);
			this.deps.requests.endAttempt(held.receiptHash, held.offerIdHex);
			const reason = `${DF_LAPSED_ABORT_REASON} before the payer's witness arrived; ${outcome}`;
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: held.offerIdHex,
				channelId: held.funding.channelId,
				error: reason
			});
			this.emit('offer:failed', { offerId: held.offerIdHex, reason });
		}
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

	/**
	 * Apply an operator policy change to the fields that carry one. Only the
	 * keys present are touched, and only the four an operator can actually set:
	 * the caps, timeouts and sweep interval are engine constants, and a live
	 * session that already passed a check is not re-judged against a new value.
	 */
	setConfig(update: {
		minAmountSat?: bigint;
		maxAmountSat?: bigint;
		allowZeroConf?: boolean;
		allowSplice?: boolean;
	}): void {
		if ('minAmountSat' in update) this.cfg.minAmountSat = update.minAmountSat;
		if ('maxAmountSat' in update) this.cfg.maxAmountSat = update.maxAmountSat;
		if (update.allowZeroConf !== undefined) {
			this.cfg.allowZeroConf = update.allowZeroConf;
		}
		if (update.allowSplice !== undefined) {
			this.cfg.allowSplice = update.allowSplice;
		}
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
		void this.admit(
			frame,
			lane.record,
			lane.keys,
			offer,
			body,
			wire.ephemeralPublicKey
		);
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
		if (this.serveWitnessFromFunding(frame, wire)) return;
		this.drop(DfOfferDropReason.NO_SESSION, frame);
	}

	/**
	 * A witness no session claimed, taken from the funding the request left in
	 * flight (issue #635).
	 *
	 * The exchange that asked for it ran in a previous life: its session and its
	 * lane keys went with the process, and the payer sends a witness once, so
	 * without this the funding strands with the payer's input unwitnessed and
	 * nothing on either side re-drives it. The lane the funding recorded is what
	 * opens the frame, and opening it is the payer's proof: only the holder of
	 * this request's envelope can seal to it.
	 */
	private serveWitnessFromFunding(
		frame: IDfInboundFrame,
		wire: IDfWireFrame
	): boolean {
		for (const held of this.deps.requests.activeFundings()) {
			// A session in this life owns the witnesses for the lane its funding
			// names, the terminal one a late-witness handler is still holding open
			// included. A session that has not earned that lane owns none of them:
			// a resumed offer whose own sign request has not left is not who the
			// payer owes the witness to, and shadowing the funding would drop the
			// one frame that can complete it.
			const live = this.state.get(held.offerIdHex);
			if (
				live?.payerEphemeralKey.toString('hex') ===
				held.funding.payerEphemeralKey
			) {
				continue;
			}
			const record = this.deps.requests.byReceiptHash(held.receiptHash);
			if (!record) continue;
			const lane = this.deps.requests.laneKeysFor(
				record,
				Buffer.from(held.funding.payerEphemeralKey, 'hex')
			);
			if (!lane) continue;
			const body = openFrame(
				lane.keys.recvKey,
				Buffer.from(record.requestId, 'hex'),
				frame.subtype,
				wire
			);
			if (!body) continue;
			let witness: IDfWitness;
			try {
				witness = decodeDfWitness(body);
			} catch {
				this.drop(DfOfferDropReason.MALFORMED_MESSAGE, frame);
				return true;
			}
			if (witness.offerId.toString('hex') !== held.offerIdHex) continue;
			void this.completeFundingFromWitness(
				frame,
				record,
				held,
				lane.keys,
				witness
			).catch((err) => {
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: held.offerIdHex,
					error: errorText(err)
				});
			});
			return true;
		}
		return false;
	}

	/**
	 * Deliver a late witness to the channel that is waiting for it, and hand
	 * back the receipt it earns.
	 *
	 * The transaction is read from the channel BEFORE the delivery: it is the
	 * receipt's subject, and a channel that has moved on cannot be asked for it
	 * afterwards. A channel that has not re-armed YET is waited for, on the same
	 * owed-witness event a resumed offer waits on: the payer marks the witness
	 * sent the moment the wire takes the frame and never offers again (sender
	 * engine ~466), so a witness dropped here is one nothing re-sends.
	 */
	private async completeFundingFromWitness(
		frame: IDfInboundFrame,
		record: IDfRequestRecord,
		held: {
			receiptHash: string;
			offerIdHex: string;
			funding: IDfAttemptFunding;
		},
		keys: IDfLaneKeys,
		witness: IDfWitness
	): Promise<void> {
		const { funding } = held;
		const channelId = Buffer.from(funding.channelId, 'hex');
		const isSplice = funding.splice;
		// The witness may be answering a funding that is already finished: what
		// the crash cost was the receipt, not the delivery (issue #658).
		const { final, settled } = await this.recoveredFunding(funding, channelId);
		if (settled) {
			this.settleCompletedFunding(
				frame.reply,
				keys,
				record,
				witness.offerId,
				funding,
				settled
			);
			return;
		}
		if (!final) {
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: held.offerIdHex,
				error: 'late witness arrived before the channel could answer for it'
			});
			return;
		}
		const [txidHex, voutText] = funding.outpoint.split(':');
		const result = this.deliverWitness(
			final,
			isSplice,
			Buffer.from(txidHex, 'hex').reverse(),
			Number(voutText),
			witness.witness
		);
		if (!result.ok) {
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: held.offerIdHex,
				error: `late witness rejected: ${result.error}`
			});
			return;
		}
		this.state.release(funding.outpoint, held.offerIdHex);
		try {
			// Tombstone before the receipt, as the session path does: the payment
			// is made, and a request that comes back looking unpaid is one a second
			// offer could fund all over again. The write also clears the mark.
			this.deps.requests.markReceiptRevealed(held.receiptHash, {
				offerIdHex: held.offerIdHex,
				fundingTxidHex: final.fundingTxidDisplay.toString('hex')
			});
		} catch (err) {
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: held.offerIdHex,
				error: `receipt tombstone not persisted: ${errorText(err)}`
			});
		}
		const complete = final.tx.ins.every((i) => i.witness.length > 0);
		const receipt = encodeDfReceipt({
			offerId: witness.offerId,
			preimage: Buffer.from(record.preimageHex, 'hex'),
			fundingTxid: final.fundingTxidDisplay,
			...(complete ? { rawTx: final.tx.toBuffer() } : {})
		});
		// A session for this offer is still driving this funding on a lane the
		// payer never answered on, and the funding is finished without it. Settle
		// it here on the receipt: left live it answers every later re-send with its
		// own ACK and sign request, ahead of the paid-receipt replay, and the
		// receipt frame below is exactly the one that can be lost (issue #635).
		const live = this.state.get(held.offerIdHex);
		if (live) {
			live.committed = true;
			live.inflight = false;
			live.terminal = true;
			live.onWitness = undefined;
			live.responses = [];
			this.state.record(
				live,
				BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
				receipt
			);
		}
		this.emitSealed(
			frame.reply,
			keys,
			Buffer.from(record.requestId, 'hex'),
			BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
			receipt
		);
		this.log(DF_LOG_OFFER_COMPLETED, { offerId: held.offerIdHex });
		this.emit('offer:completed', { offerId: held.offerIdHex });
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
		offerBytes: Buffer,
		ephemeralPublicKey: Buffer
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
			this.replay(existing, frame, keys, ephemeralPublicKey);
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
			// No session, and the request's busy mark names THIS offer over a
			// funding that is already negotiated: a restart took the session and
			// left the channel. It is answered by that funding and never by a
			// second one (issue #635).
			const attempt = this.deps.requests.attemptsFor(record.receiptHash);
			const funding =
				attempt.activeOfferId === offerIdHex ? attempt.funding : undefined;
			if (funding) {
				await this.serveResumedOffer(
					frame,
					record,
					keys,
					offer,
					offerIdHex,
					contentHash,
					funding,
					ephemeralPublicKey
				);
			} else {
				await this.admitGuarded(
					frame,
					record,
					keys,
					offer,
					offerIdHex,
					contentHash,
					ephemeralPublicKey
				);
			}
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
		contentHash: string,
		ephemeralPublicKey: Buffer
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
		// A request minted for a fixed amount is payable at that amount and no
		// other. The envelope carries it too, but that copy is the payer's; the
		// offer arrives with an amount of the payer's choosing, so this is the
		// only place the receiver's own figure is enforced.
		if (record.amountSat !== undefined) {
			if (offer.amountSat !== BigInt(record.amountSat)) {
				decline(`this request must be paid exactly ${record.amountSat} sat`);
				return;
			}
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
		//
		// Expiry first, and it is not a courtesy: an expired record answers every
		// question below as if the request were untouched (not tombstoned, no
		// active attempt, zero attempts) and takes no busy mark, so two offers
		// that await across the same expiry would each pass and each open a
		// channel for one payment.
		if (!this.deps.requests.byReceiptHash(receiptHashHex)) {
			decline('this request has expired');
			return;
		}
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
		// offer wanting the same coin. The request has to match too: the offer id
		// covers the coin and the amount only, so the same coin offered to a
		// second request at the same amount carries the same id, and a hold
		// re-taken at startup (issue #635) has no session record behind it to
		// refuse that on.
		const outpoint = outpointKey(txidHex, offer.vout);
		const reserved = this.state.reservationFor(outpoint);
		if (
			reserved &&
			(reserved.offerIdHex !== offerIdHex ||
				reserved.receiptHashHex !== receiptHashHex)
		) {
			decline('input already committed to another offer');
			return;
		}
		const now = this.now();
		this.state.reserve(
			outpoint,
			offerIdHex,
			receiptHashHex,
			now + this.cfg.sessionTtlMs
		);

		const session: IDfOfferSession = {
			offerIdHex,
			contentHash,
			receiptHashHex,
			outpoint,
			requestId: Buffer.from(record.requestId, 'hex'),
			keys,
			laneKey: frame.laneKey,
			reply: frame.reply,
			payerEphemeralKey: ephemeralPublicKey,
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
		//
		// A refusal here is the request expiring on the store's clock inside this
		// block. The session cannot run without the mark (nothing else keeps a
		// second offer off the same request), so it is unwound outright.
		if (
			!this.deps.requests.beginAttempt(
				receiptHashHex,
				offerIdHex,
				session.slotExpiresAt
			)
		) {
			this.state.forget(offerIdHex);
			this.state.release(outpoint, offerIdHex);
			decline('this request has expired');
			return;
		}
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

		const ctx: IDfSessionContext = {
			offer,
			session,
			record,
			prevTxid: prevTx.getHash(),
			paired
		};
		await this.serve(ctx, () =>
			this.startFunding(ctx, lsp, prevTx, coin.confirmed)
		);
	}

	/**
	 * Serve a re-sent offer from the funding a previous life left in flight
	 * (issue #635).
	 *
	 * Nothing is replayed and nothing is opened: the session that drove the
	 * funding was memory only, so the sign request is built again from the
	 * transaction the channel still holds and sent over the lane this offer
	 * arrived on. The offer's own fields are not re-judged and the coin is not
	 * re-read from the chain, because the bytes are the ones already admitted
	 * (the content hash says so) and the transaction they funded is negotiated
	 * and signed for by the peer. What still judges them is
	 * `fundingTransactionProblem`, which binds this offer to that transaction
	 * before the attestation is made.
	 */
	private async serveResumedOffer(
		frame: IDfInboundFrame,
		record: IDfRequestRecord,
		keys: IDfLaneKeys,
		offer: IDfOffer,
		offerIdHex: string,
		contentHash: string,
		funding: IDfAttemptFunding,
		ephemeralPublicKey: Buffer
	): Promise<void> {
		if (funding.contentHash !== contentHash) {
			// The same refusal a live duplicate gets, for the same reason: an id
			// reused with different content is not the offer this funding pays.
			this.declineUnrecorded(
				frame,
				keys,
				record,
				offer,
				'offer id reused with different content'
			);
			return;
		}
		const channelId = Buffer.from(funding.channelId, 'hex');
		// A funding whose channel completed is answered with the receipt, not
		// with a sign request for a transaction that is already the network's
		// (issue #658). Otherwise the transaction first, and no session until
		// there is one. A channel that has not re-armed yet is a WAIT, not a
		// verdict: recording a terminal session over it would answer every later
		// re-send from the refusal, and the payer answers a decline by abandoning
		// the payment the funding is still holding its coin for. Silence costs it
		// one re-send.
		const { final, settled } = await this.recoveredFunding(funding, channelId);
		if (settled) {
			this.settleCompletedFunding(
				frame.reply,
				keys,
				record,
				offer.offerId,
				funding,
				settled
			);
			return;
		}
		if (!final) {
			this.log(DF_LOG_OFFER_DROPPED, {
				reason: 'funding_not_ready',
				offerId: offerIdHex
			});
			return;
		}
		// The wait can be minutes, so the mark is read again: a witness that
		// arrived on the old lane meanwhile has already completed this funding,
		// and the request it paid is not one to ask for a signature on. The
		// payer's next re-send is answered with the receipt.
		const current = this.deps.requests.attemptsFor(record.receiptHash);
		if (current.activeOfferId !== offerIdHex || !current.funding) {
			this.log(DF_LOG_OFFER_DROPPED, {
				reason: 'funding_settled',
				offerId: offerIdHex
			});
			return;
		}
		// No concurrency cap here, unlike admission: this offer starts nothing,
		// its request already holds the funding session it is charged for, and
		// refusing it over an unrelated burst would strand a channel that only
		// this payer's witness can finish.
		const now = this.now();
		const session: IDfOfferSession = {
			offerIdHex,
			contentHash,
			receiptHashHex: record.receiptHash,
			outpoint: funding.outpoint,
			requestId: Buffer.from(record.requestId, 'hex'),
			keys,
			laneKey: frame.laneKey,
			reply: frame.reply,
			payerEphemeralKey: ephemeralPublicKey,
			responses: [],
			inflight: true,
			terminal: false,
			committed: false,
			slotExpiresAt: now + this.cfg.sessionTtlMs,
			expiresAt: Math.max(now + this.cfg.sessionTtlMs, record.expiresAt)
		};
		this.state.open(session);
		// The durable mark is the reservation's authority here, not a fresh
		// admission: the coin is already an input of a negotiated transaction.
		this.state.reserve(
			funding.outpoint,
			offerIdHex,
			record.receiptHash,
			session.expiresAt
		);
		this.state.endAdmission(offerIdHex);

		const paired =
			frame.authenticatedPeer !== undefined &&
			this.deps.isTrustedPayer(frame.authenticatedPeer);
		this.log(DF_LOG_OFFER_ACCEPTED, {
			offerId: offerIdHex,
			amountSat: offer.amountSat.toString(),
			paired,
			resumed: true
		});
		this.emit('offer:accepted', { offerId: offerIdHex, paired, resumed: true });

		const ctx: IDfSessionContext = {
			offer,
			session,
			record,
			prevTxid: Buffer.from(offer.txid).reverse(),
			paired
		};
		await this.serve(ctx, () => ({
			final: Promise.resolve(final),
			unwind: (): boolean => this.unwindFunding(funding.splice, channelId, ctx),
			isSplice: funding.splice
		}));
	}

	// ─────────────── Serving an admitted offer ───────────────

	/**
	 * Drive the funding, then hand over the receipt. Every exit releases the
	 * concurrency slot, the outpoint reservation and the request's active-offer
	 * mark; a failure additionally unwinds whatever channel work had started,
	 * and keeps the witness obligation open when that unwind is refused.
	 */
	private async serve(
		ctx: IDfSessionContext,
		start: () => IDfStartedFunding
	): Promise<void> {
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
			const started = start();
			const isSplice = started.isSplice;
			unwind = started.unwind;
			const final = await started.final;
			// The channel id the event carried is authoritative: a v2 open answers
			// to its temporary id until accept_channel2 and to its permanent one
			// afterwards, and an unwind has to name whichever is current.
			unwind = (): boolean =>
				this.unwindFunding(isSplice, final.channelId, ctx);
			const displaced = this.markFunding(ctx, final, isSplice);
			// Installed with the unwind it belongs to, not after the sign request
			// goes out: the funding is live from here, so anything that throws in
			// between (an unavailable signer, a transaction we refuse to attest
			// to) leaves the same funding a refused unwind leaves, and the request
			// and the coin are held on that rather than on how far the exchange
			// got.
			stillOwed = (): void => this.keepWitnessObligation(ctx, final, isSplice);
			witnesses = new DfWitnessQueue(ctx.session);
			// The mark already names this session's lane, and goes back to the lane
			// it displaced when the sign request does not leave: the move has to be
			// earned, but it cannot be made after the send either, because a crash
			// in that gap leaves the mark naming a lane the witness the payer is
			// answering with can never be opened on (issue #635).
			if (!this.sendSignRequest(ctx, final) && displaced) {
				this.rebindFundingLane(ctx.session, displaced);
			}
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
			this.fail(ctx, errorText(err), released, released ? null : stillOwed);
		} finally {
			witnesses?.close();
		}
	}

	/**
	 * Record the funding this session negotiated on the request, before the
	 * payer is asked to sign it (issue #635).
	 *
	 * Persist before emit, and the window it covers is the one the sign request
	 * opens: from here the transaction is final and the peer has signed for it,
	 * so a crash before the payer's witness arrives leaves a channel only that
	 * witness can finish. The mark is what a restarted receiver rebinds the
	 * payer's re-sent offer to, and what holds the request and the coin until
	 * the funding settles rather than until the session TTL.
	 *
	 * Returns the payer lane the write displaced, which is a resumed offer's
	 * previous life and nothing on a fresh admission. The caller puts it back if
	 * the sign request never leaves: this session's lane is only the one the
	 * witness is owed to once the payer has been asked for it on it.
	 */
	private markFunding(
		ctx: IDfSessionContext,
		final: IDfFinalTx,
		isSplice: boolean
	): string | undefined {
		const { session } = ctx;
		const held = this.deps.requests.attemptsFor(session.receiptHashHex);
		const displaced =
			held.activeOfferId === session.offerIdHex
				? held.funding?.payerEphemeralKey
				: undefined;
		const marked = this.deps.requests.markAttemptFunding(
			session.receiptHashHex,
			session.offerIdHex,
			{
				outpoint: session.outpoint,
				channelId: final.channelId.toString('hex'),
				splice: isSplice,
				contentHash: session.contentHash,
				payerEphemeralKey: session.payerEphemeralKey.toString('hex'),
				// Written here rather than at the delivery it proves, because the
				// delivery is the crash window: the channel retires its in-flight
				// record in the same batch that releases our tx_signatures, and a
				// txid recorded afterwards would be lost by exactly the crash it
				// exists for (issue #658).
				fundingTxid: final.fundingTxidDisplay.toString('hex')
			},
			session.expiresAt
		);
		if (!marked) {
			// The exchange goes on regardless. Withholding the sign request over a
			// storage hiccup would strand the same funding with certainty, where
			// sending it still leaves the payer able to complete it in this life.
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: session.offerIdHex,
				error: 'funding binding was not recorded on the request'
			});
		}
		return displaced;
	}

	/**
	 * Our "wallet input" IS the payer's. It is contributed and emitted on the
	 * wire like any of ours, its signWitness is never called, and our
	 * tx_signatures is withheld until its slot is filled (issue #554).
	 */
	private externalInputFor(
		ctx: IDfSessionContext,
		prevTx: bitcoin.Transaction,
		confirmed?: boolean
	): ISpliceWalletInput {
		return {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: ctx.offer.vout,
			value: ctx.offer.valueSat,
			sequence: ctx.offer.sequence,
			external: true,
			// Set from what the chain actually says, and omitted when it said
			// nothing conclusive: the fork asserted true unconditionally (defect
			// D13), which would satisfy a peer's require_confirmed_inputs over a
			// coin still in the mempool.
			...(confirmed !== undefined ? { confirmed } : {}),
			signWitness: (): Buffer[] => {
				throw new Error('external input: the witness comes from the payer');
			}
		};
	}

	/** Contribute the payer's coin to a splice or to a new channel. */
	private startFunding(
		ctx: IDfSessionContext,
		liquidityPeer: string,
		prevTx: bitcoin.Transaction,
		confirmed?: boolean
	): IDfStartedFunding {
		const input = this.externalInputFor(ctx, prevTx, confirmed);
		const spliceChannel = this.spliceTarget(ctx, liquidityPeer);
		return spliceChannel
			? { ...this.startSplice(ctx, spliceChannel, input), isSplice: true }
			: { ...this.startOpen(ctx, liquidityPeer, input), isSplice: false };
	}

	/**
	 * What this funding can still be answered with: the transaction the channel
	 * is holding for it, or the txid of one the chain says is already made
	 * (issue #658).
	 *
	 * The completed check brackets the wait rather than only preceding it. A
	 * channel holding the record when it is first read can retire it before the
	 * waiter is installed, and retiring it re-arms nothing, so that waiter is one
	 * no event will ever resolve. Its timeout says this channel cannot answer,
	 * never that the payment was not made.
	 *
	 * A retirement caught between the two reads is asked about there and then,
	 * because the trailing check alone answers too late to be of any use: it
	 * runs after the negotiation timeout, and the payer's offer timeout is the
	 * same 120 seconds and was armed before ours.
	 */
	private async recoveredFunding(
		funding: IDfAttemptFunding,
		channelId: Buffer
	): Promise<{ final: IDfFinalTx | null; settled: Buffer | null }> {
		// Read before the first await, so the record retired under us is told
		// apart from the one this channel never had.
		const wasHeld = this.pendingFinalTx(funding, channelId) !== null;
		const settled = await this.completedFundingTxid(funding, channelId);
		if (settled) return { final: null, settled };
		if (wasHeld && !this.pendingFinalTx(funding, channelId)) {
			// A chain that still says nothing is not a verdict either: the record
			// may be a rollback that comes back, so that case keeps its wait.
			const retired = await this.completedFundingTxid(funding, channelId);
			if (retired) return { final: null, settled: retired };
		}
		const final = await this.resumedFinalTx(funding, channelId);
		if (final) return { final, settled: null };
		return {
			final: null,
			settled: await this.completedFundingTxid(funding, channelId)
		};
	}

	/**
	 * The transaction a funding a previous life negotiated is waiting on a
	 * witness for, or null when this channel cannot answer for it (issue #635).
	 *
	 * Nothing is started: it comes back off the channel, or off the owed-witness
	 * event a reconnect re-arms when the channel has not answered yet.
	 */
	private async resumedFinalTx(
		funding: IDfAttemptFunding,
		channelId: Buffer
	): Promise<IDfFinalTx | null> {
		const ready = this.pendingFinalTx(funding, channelId);
		if (ready) return ready;
		const waiters = funding.splice ? this.spliceWaiters : this.v2Waiters;
		// Whatever is already parked on this outpoint is shared rather than
		// replaced. A late witness and a re-sent offer can both be waiting for the
		// same re-arm, and only the waiter the map holds is resolved: installing a
		// second one would strand the first, and when that is the witness it is the
		// one frame the payer never sends again.
		const waiter =
			waiters.get(funding.outpoint) ??
			this.awaitFinalTx(
				waiters,
				funding.outpoint,
				this.cfg.negotiationTimeoutMs
			);
		try {
			return await waiter.final;
		} catch {
			return null;
		}
	}

	/** What the channel is holding for this funding right now, if anything. */
	private pendingFinalTx(
		funding: IDfAttemptFunding,
		channelId: Buffer
	): IDfFinalTx | null {
		return this.finalTxFor(
			funding.splice
				? this.deps.getPendingSpliceTx(channelId)
				: this.deps.getPendingV2FundingTx(channelId),
			channelId,
			funding.outpoint
		);
	}

	/**
	 * The funding transaction of an exchange that already completed, or null
	 * (issue #658).
	 *
	 * A channel that reached channel_ready, or a splice that reached
	 * splice_locked, has retired the in-flight record every other recovery path
	 * reads, so a crash between the witness delivery and the receipt tombstone
	 * leaves a payment that is made and nothing to answer the payer with. The
	 * txid the funding recorded before the payer was asked to sign outlives
	 * that; the chain is what turns it into evidence, and the evidence has to be
	 * about the payer's own coin rather than about the channel, because the
	 * receipt says a specific transaction spent it. A funding that was abandoned
	 * rather than broadcast cannot produce that transaction, which is what keeps
	 * a receipt from being revealed for a payment that never happened.
	 */
	private async completedFundingTxid(
		funding: IDfAttemptFunding,
		channelId: Buffer
	): Promise<Buffer | null> {
		// A channel still holding the record answers for itself, witness and all.
		if (this.pendingFinalTx(funding, channelId)) return null;
		const txidHex = funding.fundingTxid;
		if (!txidHex) return null;
		let tx: bitcoin.Transaction;
		try {
			tx = bitcoin.Transaction.fromBuffer(
				await this.deps.chain.getTransaction(txidHex)
			);
		} catch {
			return null;
		}
		// A backend answering with some other transaction would otherwise have us
		// read the spend out of bytes nobody named.
		if (tx.getId() !== txidHex) return null;
		const [prevTxidHex, voutText] = funding.outpoint.split(':');
		const prevHash = Buffer.from(prevTxidHex, 'hex').reverse();
		const vout = Number(voutText);
		const spends = tx.ins.some(
			(input) =>
				Buffer.from(input.hash).equals(prevHash) && input.index === vout
		);
		return spends ? Buffer.from(txidHex, 'hex') : null;
	}

	/**
	 * Hand back the receipt a completed funding still owes, and tombstone the
	 * request behind it (issue #658).
	 *
	 * The session path's own success minus the delivery, which already happened:
	 * the coin is released, the request is marked paid against the transaction
	 * the chain says spends it, and the receipt goes out on the lane the payer
	 * came back on. The complete transaction is not part of it, which the
	 * receipt's rawTx field is already optional for.
	 */
	private settleCompletedFunding(
		reply: IDfLaneSender,
		keys: IDfLaneKeys,
		record: IDfRequestRecord,
		offerId: Buffer,
		funding: IDfAttemptFunding,
		fundingTxid: Buffer
	): void {
		const offerIdHex = offerId.toString('hex');
		this.state.release(funding.outpoint, offerIdHex);
		// Tombstone before the receipt, as every other success path does: the
		// payment is made, and a request that comes back looking unpaid is one a
		// second offer could fund all over again. The write also clears the busy
		// mark this request has been carrying since the crash.
		try {
			this.deps.requests.markReceiptRevealed(record.receiptHash, {
				offerIdHex,
				fundingTxidHex: fundingTxid.toString('hex')
			});
		} catch (err) {
			this.log(DF_LOG_OFFER_FAILED, {
				offerId: offerIdHex,
				error: `receipt tombstone not persisted: ${errorText(err)}`
			});
		}
		const receipt = encodeDfReceipt({
			offerId,
			preimage: Buffer.from(record.preimageHex, 'hex'),
			fundingTxid
		});
		// A session for this offer is still driving this funding on a lane the
		// payer stopped answering on. Settle it on the receipt for the reason the
		// late-witness path does: left live it answers every later re-send with its
		// own ACK and sign request, ahead of the paid-receipt replay.
		const live = this.state.get(offerIdHex);
		if (live) {
			live.committed = true;
			live.inflight = false;
			live.terminal = true;
			live.onWitness = undefined;
			live.responses = [];
			this.state.record(
				live,
				BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
				receipt
			);
		}
		this.emitSealed(
			reply,
			keys,
			Buffer.from(record.requestId, 'hex'),
			BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
			receipt
		);
		this.log(DF_LOG_OFFER_COMPLETED, { offerId: offerIdHex });
		this.emit('offer:completed', { offerId: offerIdHex });
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
	private spliceTarget(
		ctx: IDfSessionContext,
		liquidityPeer: string
	): Buffer | null {
		if (!this.cfg.allowSplice || !ctx.paired) return null;
		return this.deps.usableChannelWith(liquidityPeer);
	}

	private startOpen(
		ctx: IDfSessionContext,
		liquidityPeer: string,
		input: ISpliceWalletInput
	): { final: Promise<IDfFinalTx>; unwind: () => boolean } {
		// Registered BEFORE the open: a fully synchronous transport runs the
		// whole negotiation inside openChannelV2, and a waiter installed after
		// it would already have missed the event.
		const waiter = this.awaitFinalTx(
			this.v2Waiters,
			ctx.session.outpoint,
			this.cfg.negotiationTimeoutMs
		);
		let handle: IDfChannelHandle;
		try {
			handle = this.deps.openChannelV2(liquidityPeer, {
				fundingSatoshis: ctx.offer.amountSat,
				contribution: {
					inputs: [input],
					changeScript: ctx.offer.changeScript
				},
				// Zero-conf needs the operator's consent for DIRECT FUNDING
				// specifically, an authenticated and paired payer, and upstream's
				// own two factors (canOpenZeroConfTo and a negotiated
				// option_zeroconf). The first is not redundant with the third:
				// canOpenZeroConfTo says the operator will open a zero-conf channel
				// to this peer with its own confirmed coins, and this input is a
				// stranger's and can be double spent at depth zero. Delegating that
				// risk to the counterparty is a decision only the operator can make.
				...(this.cfg.allowZeroConf &&
				ctx.paired &&
				this.deps.canOpenZeroConfTo(liquidityPeer)
					? { trusted: true }
					: {})
			});
		} catch (err) {
			void waiter.final.catch(() => undefined);
			waiter.cancel();
			throw err;
		}
		return {
			final: waiter.final,
			unwind: (): boolean => this.unwindFunding(false, handle.channelId(), ctx)
		};
	}

	private startSplice(
		ctx: IDfSessionContext,
		channelId: Buffer,
		input: ISpliceWalletInput
	): { final: Promise<IDfFinalTx>; unwind: () => boolean } {
		const waiter = this.awaitFinalTx(
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
			void waiter.final.catch(() => undefined);
			waiter.cancel();
			throw err;
		}
		if (!result.ok) {
			void waiter.final.catch(() => undefined);
			waiter.cancel();
			throw new Error(`splice initiation failed: ${result.error}`);
		}
		return { final: waiter.final, unwind };
	}

	/**
	 * The sign request, and the attestation that makes it worth anything: this
	 * node's identity key binding the payment request to exactly this output in
	 * exactly this transaction. The transaction is hashed rather than embedded
	 * so the signed string stays fixed size; the payer recomputes the hash from
	 * the bytes it was handed.
	 *
	 * False when the lane refused the frame, so the payer was never asked.
	 */
	private sendSignRequest(ctx: IDfSessionContext, final: IDfFinalTx): boolean {
		if (final.baseFundingValueSat === undefined) {
			throw new Error(
				'the shared input value is unresolvable, so the new funding output has no floor'
			);
		}
		const problem = fundingTransactionProblem({
			tx: final.tx,
			fundingOutputIndex: final.fundingOutputIndex,
			minFundingValueSat: final.baseFundingValueSat + ctx.offer.amountSat,
			payerPrevTxid: ctx.prevTxid,
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
		return this.send(
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
		const prevTxid = ctx.prevTxid;
		let lastError = 'payer never delivered its witness';
		for (;;) {
			const remaining = deadline - this.now();
			if (remaining <= 0) throw new Error(lastError);
			const witness = await witnesses.next(remaining);
			const result = this.deliverWitness(
				final,
				isSplice,
				prevTxid,
				ctx.offer.vout,
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
		final: IDfFinalTx,
		isSplice: boolean,
		prevTxid: Buffer,
		vout: number,
		witness: Buffer[]
	): { ok: boolean; withheld?: boolean; error?: string } {
		const result = isSplice
			? this.deps.provideSpliceExternalWitness(
					final.channelId,
					prevTxid,
					vout,
					witness
			  )
			: this.deps.provideV2ExternalWitness(
					final.channelId,
					prevTxid,
					vout,
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
		const prevTxid = ctx.prevTxid;
		session.onWitness = (witness): void => {
			const result = this.deliverWitness(
				final,
				isSplice,
				prevTxid,
				ctx.offer.vout,
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
			this.state.release(session.outpoint, session.offerIdHex);
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

	private finish(
		ctx: IDfSessionContext,
		ok: boolean,
		fundingUnreleased = false
	): void {
		const { session } = ctx;
		session.inflight = false;
		session.terminal = true;
		session.onWitness = undefined;
		this.v2Waiters.delete(session.outpoint);
		this.spliceWaiters.delete(session.outpoint);
		// A funding that could not be unwound is still a funding: its late
		// witness can complete it and reveal the receipt, so neither the request
		// nor the coin is free for a second one. Both holds run to the record's
		// own expiry, which is where the late-witness handler goes too.
		if (fundingUnreleased) {
			this.deps.requests.extendAttempt(
				session.receiptHashHex,
				session.offerIdHex,
				session.expiresAt
			);
		} else {
			this.deps.requests.endAttempt(session.receiptHashHex, session.offerIdHex);
		}
		const failureHold = ok
			? undefined
			: this.now() + this.cfg.outpointCooldownMs;
		const holdUntil =
			fundingUnreleased && failureHold !== undefined
				? Math.max(session.expiresAt, failureHold)
				: failureHold;
		this.state.release(session.outpoint, session.offerIdHex, holdUntil);
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
	 * A funding that could NOT be released says the same thing: the transaction
	 * can still complete, so declining it would be a lie, and the request and
	 * the coin stay held for as long as that is true. `stillOwed` is the late
	 * witness handler that goes with it, and exists only once there is a
	 * negotiated transaction to deliver against; the holds do not depend on it.
	 */
	private fail(
		ctx: IDfSessionContext,
		reason: string,
		released: boolean,
		stillOwed: (() => void) | null
	): void {
		const { session } = ctx;
		if (!session.committed && released) {
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
		this.finish(ctx, false, !released);
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
	 * A v2 abort awaiting the peer's echo counts as a refusal for the same
	 * reason. A recorded attempt tears down only when the echo confirms the peer
	 * heard us; until then the negotiation is fully live, and a disconnect
	 * forgets the abort and resumes it. So the obligation stays open, and a late
	 * witness either completes a funding that survived or is refused by a
	 * channel that did not.
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
			const result: { ok: boolean; error?: string; pending?: boolean } =
				isSplice
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
				return false;
			}
			if (result.pending === true) {
				this.log(DF_LOG_OFFER_FAILED, {
					offerId: ctx.session.offerIdHex,
					error:
						'unwind is awaiting the peer echo, so the funding is still live'
				});
				return false;
			}
			return true;
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
	): DfFinalTxWaiter {
		let resolveFinal!: (final: IDfFinalTx) => void;
		let rejectFinal!: (reason: Error) => void;
		const final = new Promise<IDfFinalTx>((resolve, reject) => {
			resolveFinal = resolve;
			rejectFinal = reject;
		});
		let settled = false;
		const remove = (waiter: DfFinalTxWaiter): void => {
			if (waiters.get(key) === waiter) waiters.delete(key);
		};
		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			remove(waiter);
			rejectFinal(new Error('funding negotiation did not complete in time'));
		}, timeoutMs);
		timer.unref?.();
		const waiter: DfFinalTxWaiter = {
			final,
			resolve: (value): void => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				remove(waiter);
				resolveFinal(value);
			},
			cancel: (): void => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				remove(waiter);
				rejectFinal(new Error('funding negotiation was cancelled'));
			}
		};
		waiters.set(key, waiter);
		return waiter;
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
		for (const owed of pending.owedExternalInputs) {
			const key = outpointKey(
				Buffer.from(owed.prevTxid).reverse().toString('hex'),
				owed.prevOutputIndex
			);
			const waiter = waiters.get(key);
			if (!waiter) continue;
			const final = this.finalTxFor(pending, channelId, key);
			if (final) waiter.resolve(final);
			return;
		}
	}

	/**
	 * The negotiated transaction as one outpoint's session needs it, or null
	 * when this channel is not holding a witness owed for that outpoint. Read
	 * on demand as well as on the event, because a receiver restarted mid
	 * exchange has to rebuild the sign request from a channel that has already
	 * re-armed (issue #635).
	 */
	private finalTxFor(
		pending: IDfPendingV2FundingTx | IDfPendingSpliceTx | null,
		channelId: Buffer,
		outpoint: string
	): IDfFinalTx | null {
		if (!pending?.prevouts) return null;
		const prevouts = pending.prevouts;
		const owes = pending.owedExternalInputs.some(
			(owed) =>
				outpointKey(
					Buffer.from(owed.prevTxid).reverse().toString('hex'),
					owed.prevOutputIndex
				) === outpoint
		);
		if (!owes) return null;
		const common = {
			channelId: Buffer.from(channelId),
			tx: pending.tx,
			prevouts,
			owedExternalIndices: pending.owedExternalInputs.map((o) => o.inputIndex)
		};
		if ('sharedInputIndex' in pending) {
			return {
				...common,
				fundingTxidDisplay: displayTxid(pending.spliceTxid),
				fundingOutputIndex: pending.newFundingOutputIndex,
				// The new funding output carries the pre-splice capacity as well,
				// and the shared input's value IS that capacity.
				baseFundingValueSat: prevouts.values[pending.sharedInputIndex],
				sharedInputIndex: pending.sharedInputIndex
			};
		}
		return {
			...common,
			fundingTxidDisplay: displayTxid(pending.fundingTxid),
			fundingOutputIndex: pending.fundingOutputIndex,
			baseFundingValueSat: 0n
		};
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
	): boolean {
		this.state.record(session, subtype, body);
		return this.emitSealed(
			reply,
			session.keys,
			session.requestId,
			subtype,
			body
		);
	}

	/** False when the lane refused the frame outright, so nothing left. */
	private emitSealed(
		reply: IDfLaneSender,
		keys: IDfLaneKeys,
		requestId: Buffer,
		subtype: number,
		body: Buffer
	): boolean {
		const sealed = sealFrame(keys.sendKey, requestId, subtype, body);
		return reply.trySend(subtype, encodeSealedFrame(sealed));
	}

	/**
	 * Replay a session's recorded responses on the lane the duplicate arrived
	 * on, and keep the session there when they reach it. A payer whose answer
	 * was lost may well come back over a different transport, and rebinding is
	 * the only way it can be served: nothing is re-run and no second channel
	 * session begins.
	 */
	private replay(
		session: IDfOfferSession,
		frame: IDfInboundFrame,
		keys: IDfLaneKeys,
		ephemeralPublicKey: Buffer
	): void {
		// The lane goes on before the frames do, as the witness queue does around
		// a first sign request: on a synchronous lane the payer answers inside the
		// send, and only a session already naming that lane can open the witness.
		const previous = {
			keys: session.keys,
			laneKey: session.laneKey,
			reply: session.reply,
			payerEphemeralKey: session.payerEphemeralKey
		};
		session.keys = keys;
		session.laneKey = frame.laneKey;
		session.reply = frame.reply;
		session.payerEphemeralKey = ephemeralPublicKey;
		// The funding's mark moves with the session, and before the frames go for
		// the same reason: a crash between a sign request the payer answers and a
		// mark still naming the old lane leaves that answer unopenable for good.
		this.rebindFundingLane(session);
		let signRequestOut: boolean | undefined;
		let everyResponseOut = true;
		for (const response of session.responses) {
			const sent = this.emitSealed(
				frame.reply,
				keys,
				session.requestId,
				response.subtype,
				response.body
			);
			if (!sent) everyResponseOut = false;
			if (
				response.subtype === BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST
			) {
				signRequestOut = sent;
			}
		}
		// The witness answers the sign request, and the payer sends it once. So
		// the session and its funding keep the lane the sign request reached: this
		// one when the replay carried it, and otherwise the lane that already
		// holds it. Staying on a lane the sign request never left would invalidate
		// the only keys that witness can be opened with, live and after a restart
		// both, stranding the payer's input unwitnessed (#635). A session with no
		// sign request yet has nothing at stake and moves on any lane that took
		// what it did have; a lane that refused even the ACK is not one.
		if (signRequestOut ?? everyResponseOut) return;
		session.keys = previous.keys;
		session.laneKey = previous.laneKey;
		session.reply = previous.reply;
		session.payerEphemeralKey = previous.payerEphemeralKey;
		this.rebindFundingLane(session);
	}

	/**
	 * Put a payer lane on the funding, defaulting to the session's own. Nothing
	 * to do before there is a funding to name, and nothing to do when the mark
	 * already names that lane.
	 */
	private rebindFundingLane(
		session: IDfOfferSession,
		payerEphemeralKey = session.payerEphemeralKey.toString('hex')
	): void {
		const attempt = this.deps.requests.attemptsFor(session.receiptHashHex);
		if (attempt.activeOfferId !== session.offerIdHex || !attempt.funding) {
			return;
		}
		if (attempt.funding.payerEphemeralKey === payerEphemeralKey) return;
		const rebound = this.deps.requests.markAttemptFunding(
			session.receiptHashHex,
			session.offerIdHex,
			{ ...attempt.funding, payerEphemeralKey },
			session.expiresAt
		);
		if (rebound) return;
		this.log(DF_LOG_OFFER_FAILED, {
			offerId: session.offerIdHex,
			error: 'funding lane rebinding was not recorded on the request'
		});
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
