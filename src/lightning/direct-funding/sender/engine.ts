/**
 * The direct-funding payer engine (issue #613, LFBW port #532 workstream 4D).
 *
 * The payer's job is small and entirely adversarial. It decodes an envelope it
 * was handed in a URI, offers one coin, and then reads a transaction a stranger
 * built and decides whether the bytes in front of it spend that coin the way it
 * agreed. If they do it signs and the money moves. If they do not it refuses and
 * nothing has happened.
 *
 * One rule shapes everything else here:
 *
 *   **After the witness leaves the device, this call can never reject.**
 *
 * Rev 2 states it as a MUST, and the LFBW app is why it is not academic: its
 * send handler wraps this call in a try/catch and, on ANY throw, falls back to a
 * plain on-chain send of the same amount to the same address. It has no way to
 * know whether the witness went out, and it cannot be given one, because a
 * transport hiccup and a protocol decline look identical from there. A rejection
 * after the witness is out is therefore a SECOND payment. The app can be written
 * that simply precisely because this promises never to do that.
 *
 * So `send` rejects only from the pre-witness paths: a malformed envelope, an
 * amount that does not resolve, no coin, no reachable transport, a decline, a
 * sign request that failed verification, or a timeout before the witness. Once
 * the witness has been emitted, every later problem, up to and including a
 * forged receipt or a lane that dies mid-frame, resolves with what is known and
 * a `caveat` saying what was lost.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetCustomSubtype } from '../../message/custom';
import { decodeAndVerifyRequestEnvelope, IDfVerifyOptions } from '../envelope';
import {
	decodeSealedFrame,
	encodeSealedFrame,
	IDfSenderLane,
	openFrame,
	sealFrame,
	senderLaneKeysForEnvelope
} from '../frames';
import {
	decodeDfOffer,
	decodeDfOfferAck,
	decodeDfReceipt,
	decodeDfSignRequest,
	deriveOfferId,
	encodeDfOffer,
	encodeDfWitness,
	IDfOffer,
	IDfPrevout,
	IDfSignRequest,
	ownershipDigest
} from '../messages';
import {
	DirectFundingError,
	DirectFundingErrorCode,
	IDfRequestEnvelope
} from '../types';
import type { IDfInboundFrame, IDfTransport } from '../transport/types';
import { prevoutProblem, signRequestProblem } from './verify';
import {
	DF_DEFAULT_MAX_TOTAL_FEE_SAT,
	DF_LOG_FORGED_RECEIPT,
	DF_LOG_PAYMENT_RECONCILED,
	DF_LOG_SEND_CAVEAT,
	DF_LOG_SEND_COMMITTED,
	DF_LOG_SEND_COMPLETED,
	DF_LOG_SEND_REFUSED,
	DF_LOG_SEND_REPLAYED,
	DF_LOG_SEND_STARTED,
	DF_OFFER_RESEND_DELAYS_MS,
	DF_OFFER_TIMEOUT_MS,
	DF_PAYER_SEQUENCE,
	DF_POST_WITNESS_STATES,
	DF_RECEIPT_TIMEOUT_MS,
	DF_SENDER_SWEEP_INTERVAL_MS,
	IDfCoinSigner,
	IDfPaymentRecord,
	IDfSenderCoin,
	IDfSenderConfig,
	IDfSenderDeps,
	IDfSendResult
} from './types';

export interface IDfSendOptions {
	/** Required when the request fixes no amount, refused when it fixes one. */
	amountSat?: bigint;
	/**
	 * Ceiling on our own cost above the amount (rev 2 `max_total_fee_sat`). The
	 * daemon accepts `feeHeadroomSats` as a documented alias for the same number.
	 */
	maxTotalFeeSat?: bigint;
	/** Clock override for the envelope's expiry check. */
	now?: number;
}

type ResolvedConfig = Required<IDfSenderConfig>;

/** What one send needs end to end, all of it pinned before the first frame. */
interface IDfAttempt {
	env: IDfRequestEnvelope;
	record: IDfPaymentRecord;
	offer: IDfOffer;
	/**
	 * The encoded offer, byte for byte as it was first sent. A resend and a
	 * resumed attempt re-emit THESE bytes: the receiver's replay is keyed on the
	 * offer's content hash, and a Schnorr ownership proof is not deterministic,
	 * so re-encoding an equivalent offer would read as an id reused with
	 * different content and be refused (4C's admission, step 2).
	 */
	offerBody: Buffer;
	coin: IDfSenderCoin;
	signer: IDfCoinSigner;
	/** Prev txid in INTERNAL byte order, as transaction inputs carry it. */
	prevTxid: Buffer;
}

/** The exchange's control surface, handed to the frame handlers. */
interface IDfExchangeControl {
	offerIdHex: string;
	sawSignRequest(): boolean;
	markSignRequest(): void;
	committed(): boolean;
	commit(witness: Buffer[]): void;
	done(caveat?: string): void;
	fail(err: Error): void;
}

export class DirectFundingSender {
	private readonly cfg: ResolvedConfig;
	/**
	 * Sends running right now, by request id. Two concurrent calls for one
	 * request share ONE promise: without this the second would re-run coin
	 * selection, and because the first had frozen the original coin it would
	 * pick a DIFFERENT one, produce a different offer id, and genuinely pay
	 * twice (defect D6). 4C's idempotency is keyed on the offer, which cannot
	 * help, because the retry never gets that far.
	 */
	private readonly inflight = new Map<string, Promise<IDfSendResult>>();
	private sweepTimer: NodeJS.Timeout | null = null;

	constructor(
		private readonly deps: IDfSenderDeps,
		config: IDfSenderConfig = {}
	) {
		this.cfg = {
			sequence: config.sequence ?? DF_PAYER_SEQUENCE,
			defaultMaxTotalFeeSat:
				config.defaultMaxTotalFeeSat ?? DF_DEFAULT_MAX_TOTAL_FEE_SAT,
			offerResendDelaysMs:
				config.offerResendDelaysMs ?? DF_OFFER_RESEND_DELAYS_MS,
			offerTimeoutMs: config.offerTimeoutMs ?? DF_OFFER_TIMEOUT_MS,
			receiptTimeoutMs: config.receiptTimeoutMs ?? DF_RECEIPT_TIMEOUT_MS,
			sweepIntervalMs: config.sweepIntervalMs ?? DF_SENDER_SWEEP_INTERVAL_MS
		};
	}

	// ─────────────── Lifecycle ───────────────

	/** Arm the reconciliation sweep over records whose funding is in flight. */
	start(): void {
		if (this.sweepTimer) return;
		this.sweepTimer = setInterval(() => {
			void this.reconcile();
		}, this.cfg.sweepIntervalMs);
		this.sweepTimer.unref?.();
	}

	stop(): void {
		if (!this.sweepTimer) return;
		clearInterval(this.sweepTimer);
		this.sweepTimer = null;
	}

	// ─────────────── The send ───────────────

	/**
	 * Pay a direct-funding request by funding the receiver's channel from one of
	 * our coins.
	 *
	 * Rejects only before the witness leaves the device. In every rejecting path
	 * nothing was signed and nothing spent.
	 */
	async send(
		encodedRequest: string,
		opts: IDfSendOptions = {}
	): Promise<IDfSendResult> {
		const env = this.decode(encodedRequest, opts.now);
		const amountSat = resolveAmount(env, opts.amountSat);
		const requestIdHex = env.requestId.toString('hex');

		const running = this.inflight.get(requestIdHex);
		if (running) {
			this.log(DF_LOG_SEND_REPLAYED, {
				requestId: requestIdHex,
				reason: 'in flight'
			});
			return running;
		}
		// The map entry has to exist before the first await inside begin(), or a
		// second caller arriving in that window starts a second attempt.
		const run = this.begin(env, requestIdHex, amountSat, opts).then(
			(attempt) => (attempt ? this.run(attempt) : this.replay(requestIdHex))
		);
		this.inflight.set(requestIdHex, run);
		try {
			return await run;
		} finally {
			this.inflight.delete(requestIdHex);
		}
	}

	/** Every payment this device has a record of. */
	payments(): IDfPaymentRecord[] {
		return this.deps.payments.list();
	}

	/**
	 * Advance the records whose funding may be on chain, using the only two
	 * facts a wallet can state honestly: whether the funding transaction is known
	 * and confirmed, and whether some OTHER confirmed transaction spent the coin.
	 *
	 * Mempool absence is never failure, and cancellation is not built here: rev 2
	 * makes both a deliberate, user-visible act rather than an automatic one.
	 */
	async reconcile(): Promise<void> {
		for (const record of this.deps.payments.pending()) {
			const fundingTxid = record.fundingTxid;
			const status = fundingTxid
				? this.deps.wallet.txStatus(fundingTxid)
				: null;
			if (status?.confirmed) {
				this.settle(record, 'CONFIRMED');
				continue;
			}
			if (status?.known) {
				if (record.status !== 'MEMPOOL_SEEN') {
					this.deps.payments.update(record.requestId, {
						status: 'MEMPOOL_SEEN'
					});
					this.log(DF_LOG_PAYMENT_RECONCILED, {
						requestId: record.requestId,
						status: 'MEMPOOL_SEEN'
					});
				}
				continue;
			}
			// A conflict, and only once it has CONFIRMED. The coin is ours, so the
			// only thing that can double-spend it is this wallet, which is what the
			// freeze exists to prevent; if one got through anyway the payment is
			// genuinely dead and holding the coin buys nothing.
			const conflict = this.deps.wallet.confirmedSpendOf(
				record.spentTxid,
				record.spentVout
			);
			if (conflict && conflict !== fundingTxid) {
				this.settle(
					record,
					'FAILED',
					`conflicting spend ${conflict} confirmed`
				);
			}
		}
	}

	/**
	 * Settle a record and release the coin it held.
	 *
	 * The freeze is not housekeeping: it is what stops this wallet
	 * conflict-spending a funding it has already signed for, so it is lifted only
	 * once the coin is provably gone (the funding confirmed, or a conflict won).
	 * An operator abandoning a payment lifts it deliberately, with
	 * `POST /utxo/unfreeze` over the outpoint this record names.
	 */
	private settle(
		record: IDfPaymentRecord,
		status: 'CONFIRMED' | 'FAILED',
		reason?: string
	): void {
		this.deps.payments.update(record.requestId, {
			status,
			frozen: false,
			...(reason ? { reason } : {})
		});
		this.log(DF_LOG_PAYMENT_RECONCILED, {
			requestId: record.requestId,
			status,
			...(reason ? { reason } : {})
		});
		void this.deps.wallet
			.unfreezeUtxo(record.spentTxid, record.spentVout)
			.catch(() => undefined);
	}

	// ─────────────── Setting an attempt up ───────────────

	private decode(encoded: string, now?: number): IDfRequestEnvelope {
		const verify: IDfVerifyOptions = {
			expectedChainHash: this.deps.chainHash(),
			...(now !== undefined ? { now } : {})
		};
		return decodeAndVerifyRequestEnvelope(encoded, verify);
	}

	/**
	 * Resolve this request to an attempt, or to null when it already has one that
	 * has run its course.
	 *
	 * The coin, the offer bytes and the change script are pinned to the REQUEST
	 * at the first attempt and re-read on every later one. That is what makes a
	 * retried send safe: a crash mid-exchange resumes the SAME offer over the
	 * SAME coin, which the receiver answers idempotently, instead of committing a
	 * second coin to one payment.
	 */
	private async begin(
		env: IDfRequestEnvelope,
		requestIdHex: string,
		amountSat: bigint,
		opts: IDfSendOptions
	): Promise<IDfAttempt | null> {
		const existing = this.deps.payments.get(requestIdHex);
		if (existing) {
			// The amount first, and ahead of the replay: the offer id is derived
			// over the amount, so a caller asking to pay a different one is asking
			// for a different offer against a coin this request has already
			// committed. Answering it with the recorded attempt would report a
			// payment of one amount as a payment of another.
			if (existing.amountSat !== amountSat.toString()) {
				throw new DirectFundingError(
					DirectFundingErrorCode.AMOUNT_MISMATCH,
					`this request already has an attempt for ${existing.amountSat} sat`
				);
			}
			if (DF_POST_WITNESS_STATES.has(existing.status)) return null;
			if (existing.status === 'ABORTED') return null;
			return this.resume(env, existing);
		}
		const maxTotalFeeSat =
			opts.maxTotalFeeSat ?? this.cfg.defaultMaxTotalFeeSat;
		if (maxTotalFeeSat < 0n) {
			throw new DirectFundingError(
				DirectFundingErrorCode.AMOUNT_MISMATCH,
				'maxTotalFeeSat must not be negative'
			);
		}
		const coin = this.selectCoin(amountSat, maxTotalFeeSat);
		const signer = this.signerFor(coin);
		const changeScript = await this.deps.wallet.changeScript();
		const txid = Buffer.from(coin.txidHex, 'hex');
		const offerId = deriveOfferId(txid, coin.vout, amountSat);
		const offer: IDfOffer = {
			offerId,
			amountSat,
			txid,
			vout: coin.vout,
			valueSat: coin.valueSat,
			sequence: this.cfg.sequence,
			changeScript,
			maxTotalFeeSat,
			receiptHash: env.receiptHash,
			ownership: {
				pubkey: signer.ownershipPubkey,
				// The proof costs the receiver nothing to check and saves it a whole
				// channel session on a coin we cannot actually spend.
				signature: signer.signOwnership(
					ownershipDigest(offerId, txid, coin.vout, amountSat)
				)
			}
		};
		const offerBody = encodeDfOffer(offer);
		const now = this.now();
		const record: IDfPaymentRecord = {
			requestId: requestIdHex,
			receiptHash: env.receiptHash.toString('hex'),
			receiverNodeId: env.receiverNodeId.toString('hex'),
			amountSat: amountSat.toString(),
			maxTotalFeeSat: maxTotalFeeSat.toString(),
			offerId: offerId.toString('hex'),
			offerBody: offerBody.toString('hex'),
			spentTxid: coin.txidHex,
			spentVout: coin.vout,
			spentValueSat: coin.valueSat.toString(),
			changeScript: changeScript.toString('hex'),
			status: 'CREATED',
			createdAt: now,
			updatedAt: now
		};
		if (!this.deps.payments.open(record)) {
			// A coin offered against a record nothing remembers opening is a coin a
			// retry offers a second time. Refuse while that is still free.
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'direct-funding payment record could not be persisted'
			);
		}
		this.log(DF_LOG_SEND_STARTED, {
			requestId: requestIdHex,
			offerId: record.offerId,
			amountSat: amountSat.toString(),
			resumed: false
		});
		return {
			env,
			record,
			offer,
			offerBody,
			coin,
			signer,
			prevTxid: Buffer.from(txid).reverse()
		};
	}

	/**
	 * Rebuild an attempt from a record whose exchange did not finish. Nothing is
	 * chosen again: the offer comes back off the record verbatim, and only the
	 * signer is looked up, because a key is not something to persist.
	 */
	private resume(
		env: IDfRequestEnvelope,
		record: IDfPaymentRecord
	): IDfAttempt {
		const coin = this.deps.wallet
			.listSpendable()
			.find(
				(c) => c.txidHex === record.spentTxid && c.vout === record.spentVout
			);
		if (!coin) {
			// The coin went somewhere else before the offer was ever answered. The
			// attempt can never complete, and leaving the record live would wedge the
			// request against every later retry, so it is closed here and the
			// refusal is what a retry replays.
			this.deps.payments.update(record.requestId, {
				status: 'ABORTED',
				reason: `the offered coin ${record.spentTxid}:${record.spentVout} is no longer spendable`
			});
			throw new DirectFundingError(
				DirectFundingErrorCode.NO_SUITABLE_UTXO,
				`the coin this request was offered, ${record.spentTxid}:${record.spentVout}, is no longer spendable`
			);
		}
		const offerBody = Buffer.from(record.offerBody, 'hex');
		this.log(DF_LOG_SEND_STARTED, {
			requestId: record.requestId,
			offerId: record.offerId,
			amountSat: record.amountSat,
			resumed: true
		});
		return {
			env,
			record,
			offer: decodeDfOffer(offerBody),
			offerBody,
			coin,
			signer: this.signerFor(coin),
			prevTxid: Buffer.from(record.spentTxid, 'hex').reverse()
		};
	}

	private signerFor(coin: IDfSenderCoin): IDfCoinSigner {
		const signer = this.deps.wallet.signerFor(coin);
		if (!signer) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NO_SUITABLE_UTXO,
				`this wallet cannot sign for ${coin.txidHex}:${coin.vout}`
			);
		}
		return signer;
	}

	/**
	 * The largest single coin covering the payment and its fee ceiling.
	 *
	 * Single-input offers are the protocol's shape: the receiver verifies ONE
	 * ownership proof and holds ONE witness slot. What changes from the fork is
	 * the refusal, which was a bare Error indistinguishable from a transport
	 * failure; those two want opposite things from the caller, so they carry
	 * different codes.
	 */
	private selectCoin(amountSat: bigint, maxTotalFeeSat: bigint): IDfSenderCoin {
		const need = amountSat + maxTotalFeeSat;
		let best: IDfSenderCoin | null = null;
		for (const coin of this.deps.wallet.listSpendable()) {
			if (coin.valueSat < need) continue;
			if (!best || coin.valueSat > best.valueSat) best = coin;
		}
		if (!best) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NO_SUITABLE_UTXO,
				`direct funding needs one coin worth at least ${need} sat ` +
					`(${amountSat} sat plus the ${maxTotalFeeSat} sat fee allowance)`
			);
		}
		return best;
	}

	/** The recorded outcome of a request whose attempt has already run. */
	private replay(requestIdHex: string): IDfSendResult {
		const record = this.deps.payments.get(requestIdHex);
		if (!record) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'the recorded attempt for this request is gone'
			);
		}
		this.log(DF_LOG_SEND_REPLAYED, {
			requestId: requestIdHex,
			status: record.status
		});
		if (record.status === 'ABORTED') {
			// Pre-witness and terminal: nothing was spent, and rev 2 allows the
			// caller its fallback here. Replaying the refusal rather than re-running
			// keeps that decision one the caller makes once.
			throw new DirectFundingError(
				DirectFundingErrorCode.OFFER_DECLINED,
				record.reason ?? 'this request was already attempted and abandoned'
			);
		}
		return resultFrom(record);
	}

	// ─────────────── The exchange ───────────────

	private async run(attempt: IDfAttempt): Promise<IDfSendResult> {
		try {
			return await this.deps.registry.run(
				attempt.env.transports,
				{
					requestId: attempt.env.requestId,
					receiverNodeId: attempt.env.receiverNodeId
				},
				(lane) => this.exchange(attempt, lane)
			);
		} catch (err) {
			// Everything reaching here is pre-witness: `exchange` resolves once the
			// witness is out, and the registry only propagates what a lane raised
			// before that. So the coin is unspent, and the record is closed with the
			// reason a retry then replays instead of re-offering.
			const reason = errorText(err);
			this.deps.payments.update(attempt.record.requestId, {
				status: 'ABORTED',
				reason
			});
			this.log(DF_LOG_SEND_REFUSED, {
				requestId: attempt.record.requestId,
				offerId: attempt.record.offerId,
				reason
			});
			throw err;
		}
	}

	/**
	 * One lane's worth of the protocol: offer, ack, sign request, witness,
	 * receipt.
	 *
	 * Every timer and subscription installed here is released by `finish`, on
	 * every exit. The fork's resend fired from a bare setTimeout straight into a
	 * send that throws `Not connected to peer`, which is an uncaughtException
	 * with no caller to catch it (defects D2 and D3); here the resend goes
	 * through `trySend`, which reports instead of throwing, and the schedule is
	 * unwound the way `spliceInAndWait`'s cancelWait does.
	 */
	private exchange(
		attempt: IDfAttempt,
		lane: IDfTransport
	): Promise<IDfSendResult> {
		const keys = senderLaneKeysForEnvelope(attempt.env);
		const offerIdHex = attempt.offer.offerId.toString('hex');

		return new Promise<IDfSendResult>((resolve, reject) => {
			/** Set the instant the witness leaves. From here nothing may reject. */
			let committed = false;
			let signRequestSeen = false;
			let settled = false;
			const timers: NodeJS.Timeout[] = [];
			let unsubscribe: (() => void) | null = null;

			const finish = (): void => {
				for (const timer of timers) clearTimeout(timer);
				timers.length = 0;
				unsubscribe?.();
				unsubscribe = null;
			};
			/** Resolve with what is known, plus what was lost getting there. */
			const done = (caveat?: string): void => {
				if (settled) return;
				settled = true;
				finish();
				if (caveat) {
					this.log(DF_LOG_SEND_CAVEAT, {
						requestId: attempt.record.requestId,
						caveat
					});
				}
				const record =
					this.deps.payments.get(attempt.record.requestId) ?? attempt.record;
				resolve({ ...resultFrom(record), ...(caveat ? { caveat } : {}) });
			};
			/**
			 * The whole contract in one function. Before the witness is out a problem
			 * is a refusal; after it, the funding may already be broadcast, and a
			 * rejection would prompt the caller into a second payment for the same
			 * request, so it becomes a caveat on a success.
			 */
			const fail = (err: Error): void => {
				if (settled) return;
				if (committed) {
					done(err.message);
					return;
				}
				settled = true;
				finish();
				reject(err);
			};
			const at = (delayMs: number, fn: () => void): void => {
				const timer = setTimeout(() => {
					try {
						fn();
					} catch (err) {
						fail(asError(err));
					}
				}, delayMs);
				timer.unref?.();
				timers.push(timer);
			};
			const sealed = (
				subtype: number,
				body: Buffer,
				opening: boolean
			): Buffer =>
				encodeSealedFrame(
					sealFrame(keys.keys.sendKey, attempt.env.requestId, subtype, body),
					opening
						? {
								requestId: attempt.env.requestId,
								ephemeralPublicKey: keys.ephemeralPublicKey
						  }
						: undefined
				);

			const ctl: IDfExchangeControl = {
				offerIdHex,
				sawSignRequest: () => signRequestSeen,
				markSignRequest: () => {
					signRequestSeen = true;
				},
				committed: () => committed,
				commit: (witness): void => {
					const payload = sealed(
						BeignetCustomSubtype.DIRECT_FUNDING_WITNESS,
						encodeDfWitness({ offerId: attempt.offer.offerId, witness }),
						false
					);
					// The latch goes up BEFORE the send, not after. A synchronous lane
					// (payer and receiver in one process, which rev 2 names as the
					// intended first deployment) runs the receiver's whole answer inside
					// this call, so a decline or a malformed receipt arrives while this
					// line is still on the stack. Setting the latch afterwards made
					// those read as PRE-witness problems and reject a call whose
					// witness was already out, which is the double payment the whole
					// contract exists to prevent.
					committed = true;
					try {
						lane.send(BeignetCustomSubtype.DIRECT_FUNDING_WITNESS, payload);
					} catch (err) {
						// The lane refused the frame outright, so the witness never
						// reached the wire and nothing can have answered it: a refusal is
						// still free. (A throw from a HANDLER cannot arrive here; the
						// subscription isolates those, as the node's own dispatch does.)
						committed = false;
						fail(asError(err));
						return;
					}
					if (settled) return;
					// The receipt is proof, not delivery. Its own, shorter window opens
					// here, and its expiry is a SUCCESS.
					for (const timer of timers) clearTimeout(timer);
					timers.length = 0;
					at(this.cfg.receiptTimeoutMs, () =>
						done('the receiver did not send a delivery receipt in time')
					);
				},
				done,
				fail
			};

			unsubscribe = lane.onMessage((frame) => {
				try {
					this.onFrame(attempt, keys, frame, ctl);
				} catch (err) {
					fail(asError(err));
				}
			});

			// The first frame is what tells the registry whether this lane got
			// established: a throw here has put nothing on the wire, so the registry
			// may fall through to the next descriptor.
			try {
				lane.send(
					BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
					sealed(
						BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
						attempt.offerBody,
						true
					)
				);
			} catch (err) {
				finish();
				reject(asError(err));
				return;
			}
			if (
				this.deps.payments.get(attempt.record.requestId)?.status === 'CREATED'
			) {
				this.deps.payments.update(attempt.record.requestId, {
					status: 'OFFERED'
				});
			}
			// A synchronous lane (payer and receiver in one process, which rev 2
			// names as the intended first deployment) can have run the whole exchange
			// inside that send, so nothing below may assume it is still open.
			if (settled) return;

			at(this.cfg.offerTimeoutMs, () =>
				fail(
					new DirectFundingError(
						DirectFundingErrorCode.EXCHANGE_TIMEOUT,
						'the receiver did not complete the funding exchange in time'
					)
				)
			);
			for (const delay of this.cfg.offerResendDelaysMs) {
				at(delay, () => {
					if (signRequestSeen || committed) return;
					// Offers are idempotent at the receiver, which replays its recorded
					// responses for a duplicate and starts nothing twice, so re-sending
					// one lost in transit is safe. trySend, never send: this fires from
					// a timer, where a throw has no caller.
					lane.trySend(
						BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
						sealed(
							BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
							attempt.offerBody,
							true
						)
					);
				});
			}
		});
	}

	/** One inbound frame, opened and dispatched. */
	private onFrame(
		attempt: IDfAttempt,
		keys: IDfSenderLane,
		frame: IDfInboundFrame,
		ctl: IDfExchangeControl
	): void {
		const wire = decodeSealedFrame(frame.payload);
		if (!wire) return;
		const body = openFrame(
			keys.keys.recvKey,
			attempt.env.requestId,
			frame.subtype,
			wire
		);
		// Silence, as everywhere in this protocol: a frame we cannot open was not
		// sealed for us.
		if (!body) return;

		if (frame.subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK) {
			const ack = decodeDfOfferAck(body);
			if (ack.offerId.toString('hex') !== ctl.offerIdHex) return;
			if (ack.accepted) return;
			// A decline arriving after our witness cannot undo the funding, and 4C
			// never declines a committed session. Ignoring it keeps the never-reject
			// contract absolute rather than conditional on a well-behaved peer.
			if (ctl.committed()) return;
			ctl.fail(
				new DirectFundingError(
					DirectFundingErrorCode.OFFER_DECLINED,
					ack.reason
						? `the receiver declined the offer: ${ack.reason}`
						: 'the receiver declined the offer'
				)
			);
			return;
		}

		if (frame.subtype === BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT) {
			this.onReceipt(attempt, decodeDfReceipt(body), ctl);
			return;
		}

		if (frame.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST) {
			return;
		}
		const request = decodeDfSignRequest(body);
		if (request.offerId.toString('hex') !== ctl.offerIdHex) return;
		// A duplicate sign request is the receiver replaying its recorded
		// responses. The witness is out or on its way; signing again would put a
		// second signature over the same input for no reason.
		if (ctl.sawSignRequest()) return;
		ctl.markSignRequest();
		this.honor(attempt, request, ctl).catch((err) => ctl.fail(asError(err)));
	}

	private onReceipt(
		attempt: IDfAttempt,
		receipt: ReturnType<typeof decodeDfReceipt>,
		ctl: IDfExchangeControl
	): void {
		if (receipt.offerId.toString('hex') !== ctl.offerIdHex) return;
		const hash = crypto
			.createHash('sha256')
			.update(receipt.preimage)
			.digest('hex');
		if (hash !== attempt.record.receiptHash) {
			// The fork ignored this, which is right, and said nothing, which is not:
			// a receipt that does not open the request's hash is a party claiming a
			// delivery it cannot prove.
			this.log(DF_LOG_FORGED_RECEIPT, {
				requestId: attempt.record.requestId,
				offerId: ctl.offerIdHex
			});
			return;
		}
		this.deps.payments.update(attempt.record.requestId, {
			receiptPreimage: receipt.preimage.toString('hex'),
			fundingTxid: receipt.fundingTxid.toString('hex'),
			...(receipt.rawTx ? { broadcastTx: receipt.rawTx.toString('hex') } : {})
		});
		this.log(DF_LOG_SEND_COMPLETED, {
			requestId: attempt.record.requestId,
			offerId: ctl.offerIdHex
		});
		ctl.done();
	}

	/**
	 * Verify, freeze, sign, persist, emit. In that order, and the order is the
	 * whole safety argument:
	 *
	 *  - verification runs first, so nothing is signed over bytes we refuse;
	 *  - the freeze lands before the record, so a record that says SIGNED_PENDING
	 *    always describes a coin this wallet has stopped selecting;
	 *  - the record lands before the witness, so a crash immediately after the
	 *    send still leaves the attestation, the transaction and our witness on
	 *    disk (RECOVERY-PROTOCOL 5.10, disposition D1);
	 *  - and only then does the witness leave, after which nothing may reject.
	 */
	private async honor(
		attempt: IDfAttempt,
		request: IDfSignRequest,
		ctl: IDfExchangeControl
	): Promise<void> {
		const refuse = (problem: string): void =>
			ctl.fail(
				new DirectFundingError(
					DirectFundingErrorCode.SIGN_REQUEST_REFUSED,
					problem
				)
			);
		let tx: bitcoin.Transaction;
		try {
			tx = bitcoin.Transaction.fromBuffer(request.rawTx);
		} catch {
			refuse('sign request does not carry a decodable transaction');
			return;
		}
		const checked = signRequestProblem({
			request,
			tx,
			offerId: attempt.offer.offerId,
			payerPrevTxid: attempt.prevTxid,
			payerVout: attempt.offer.vout,
			payerValueSat: attempt.offer.valueSat,
			sequence: attempt.offer.sequence,
			changeScript: attempt.offer.changeScript,
			amountSat: attempt.offer.amountSat,
			maxTotalFeeSat: attempt.offer.maxTotalFeeSat,
			receiverNodeId: attempt.env.receiverNodeId,
			ownsOutpoint: (txid, vout) => this.deps.wallet.ownsOutpoint(txid, vout)
		});
		if ('problem' in checked) {
			refuse(checked.problem);
			return;
		}
		const { inputIndex } = checked.verdict;
		const prevoutIssue = await prevoutProblem(
			tx,
			request.prevouts,
			inputIndex,
			attempt.coin.script,
			attempt.offer.valueSat,
			attempt.signer.kind === 'p2tr',
			(txidHex) => this.deps.wallet.getTransaction(txidHex)
		);
		if (prevoutIssue) {
			refuse(prevoutIssue);
			return;
		}

		// The witness may broadcast the moment it lands, so the coin stops being
		// selectable here rather than afterwards. Freezes are persisted and matched
		// by outpoint, so a confirmation-height change cannot lift one.
		const frozen = await this.deps.wallet
			.freezeUtxo(attempt.coin.txidHex, attempt.coin.vout)
			.catch(() => false);
		if (!frozen) {
			refuse(
				'could not reserve the offered coin against our own coin selection'
			);
			return;
		}
		const release = async (): Promise<void> => {
			await this.deps.wallet
				.unfreezeUtxo(attempt.coin.txidHex, attempt.coin.vout)
				.catch(() => undefined);
		};

		let witness: Buffer[];
		try {
			witness = attempt.signer.signInput(tx, inputIndex, {
				scripts: request.prevouts.map((p: IDfPrevout) => p.script),
				values: request.prevouts.map((p: IDfPrevout) => p.valueSat)
			});
		} catch (err) {
			await release();
			ctl.fail(asError(err));
			return;
		}

		const persisted = this.deps.payments.commitWitness(
			attempt.record.requestId,
			{
				attestation: {
					fundingOutputIndex: request.attestation.fundingOutputIndex,
					localFundingPubkey:
						request.attestation.localFundingPubkey.toString('hex'),
					remoteFundingPubkey:
						request.attestation.remoteFundingPubkey.toString('hex'),
					signature: request.attestation.signature.toString('hex')
				},
				negotiatedTx: request.rawTx.toString('hex'),
				witness: witness.map((item) => item.toString('hex')),
				fundingTxid: checked.verdict.fundingTxidDisplay,
				frozen: true
			}
		);
		if (!persisted) {
			// The last moment a refusal is free. A witness emitted against a record
			// that never landed is a spend nothing on this device remembers making.
			await release();
			ctl.fail(
				new DirectFundingError(
					DirectFundingErrorCode.NOT_PERSISTED,
					'the signed funding could not be persisted, so the witness was withheld'
				)
			);
			return;
		}
		this.log(DF_LOG_SEND_COMMITTED, {
			requestId: attempt.record.requestId,
			offerId: attempt.record.offerId,
			fundingTxid: checked.verdict.fundingTxidDisplay
		});
		// Past this call nothing may reject.
		ctl.commit(witness);
	}

	// ─────────────── Odds and ends ───────────────

	private now(): number {
		return this.deps.now ? this.deps.now() : Date.now();
	}

	private log(action: string, data: Record<string, unknown>): void {
		try {
			this.deps.log?.(action, data);
		} catch {
			// A throwing log observer must not abandon a payment.
		}
	}
}

// ─────────────── Helpers ───────────────

/**
 * The amount this send pays. A request that fixes one is payable at that amount
 * and no other; one that does not needs the caller to say.
 */
function resolveAmount(env: IDfRequestEnvelope, requested?: bigint): bigint {
	if (env.amountSat !== undefined) {
		if (requested !== undefined && requested !== env.amountSat) {
			throw new DirectFundingError(
				DirectFundingErrorCode.AMOUNT_MISMATCH,
				`the payment request fixes the amount at ${env.amountSat} sat`
			);
		}
		return env.amountSat;
	}
	if (requested === undefined || requested <= 0n) {
		throw new DirectFundingError(
			DirectFundingErrorCode.AMOUNT_REQUIRED,
			'an amount is required: this payment request does not fix one'
		);
	}
	return requested;
}

function resultFrom(record: IDfPaymentRecord): IDfSendResult {
	return {
		offerId: record.offerId,
		spentTxid: record.spentTxid,
		spentVout: record.spentVout,
		amountSat: Number(record.amountSat),
		attested: record.attestation !== undefined,
		receiptPreimageHex: record.receiptPreimage ?? null,
		status: record.status,
		...(record.fundingTxid ? { fundingTxid: record.fundingTxid } : {}),
		...(record.negotiatedTx ? { rawTxHex: record.negotiatedTx } : {}),
		...(record.broadcastTx ? { broadcastTxHex: record.broadcastTx } : {})
	};
}

function asError(err: unknown): Error {
	return err instanceof Error ? err : new Error(String(err));
}

function errorText(err: unknown): string {
	if (err instanceof DirectFundingError) return `${err.code}: ${err.message}`;
	return err instanceof Error ? err.message : String(err);
}
