/**
 * The outstanding-request store (rev 2 "Request lifecycle requirements").
 *
 * Every envelope handed out is backed by a record holding secrets the
 * receiver needs to answer it: the receipt preimage, the per-request
 * encryption private key, and the blinded path's private path_id. Without
 * durability, a restart makes every request already in the wild unpayable and
 * loses the preimage that acknowledges a payment.
 *
 * Storage is the ENCRYPTED wallet-data store, not a file beside it. That is a
 * deliberate departure from the fork, which wrote
 * `<dataDir>/direct-funding-requests.json` with a bare writeFileSync: the mode
 * 0600 applies only at creation, so an existing file with looser permissions
 * is never corrected, and the write is not atomic, so a crash mid-write leaves
 * the restore path logging and continuing with nothing restored. Wallet data
 * is encrypted at rest and lands inside the surrounding SQLite transaction.
 * The file path was never a consumer contract; nothing reads it.
 */

import { randomBytes, sha256 } from '../crypto/provider';
import type { IDfLaneKeys, IDfWireFrame } from './frames';
import { mintRequestEncryptionKeys, receiverLaneKeys } from './frames';
import { getPublicKey } from '../crypto/ecdh';
import type {
	IDfAttemptFunding,
	IDfReceivedRecord,
	IDfRequestRecord
} from './types';
import {
	DF_DEFAULT_REQUEST_TTL_MS,
	DF_MAX_AMOUNT_SAT,
	DF_MAX_REQUEST_TTL_MS,
	DF_NODE_ID_BYTES,
	DF_OFFER_ID_BYTES,
	DF_PATH_SECRET_BYTES,
	DF_PREIMAGE_BYTES,
	DF_REQUEST_ID_BYTES,
	DirectFundingError,
	DirectFundingErrorCode,
	malformed
} from './types';

/** Wallet-data key holding the whole outstanding set. */
export const DF_REQUESTS_STORAGE_KEY = 'df:requests';

/** Requests one node may have outstanding at once, each holding secrets. */
export const DF_DEFAULT_MAX_OUTSTANDING = 256;

/** How often the expiry sweep runs once `start()` has been called. */
export const DF_DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/** Wallet-data key holding the record of every payment received (issue #1893). */
export const DF_RECEIVED_STORAGE_KEY = 'df:received';

/**
 * How long a received record is kept, and how many are held at once: the
 * figures the payer's own records use, for the same reasons. A client coming
 * back after a week to ask whether its request was paid still gets the truth,
 * and the set, written whole on every change, stays bounded. A client that has
 * seen the payment keeps it in its own history from then on.
 */
export const DF_RECEIVED_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const DF_MAX_RECEIVED_RECORDS = 512;

/**
 * The narrow slice of the node's storage this needs, declared here rather
 * than imported whole so the engine can be driven by a map in tests (the
 * shape 3A established with IJitManagerDeps).
 */
export interface IDfRequestStoreDeps {
	storage?: {
		saveWalletData(key: string, value: string): void;
		loadWalletData(key: string): string | null;
	};
	now?: () => number;
}

export interface IDfRequestStoreConfig {
	/** Life of a minted request, capped at DF_MAX_REQUEST_TTL_MS. */
	requestTtlMs?: number;
	maxOutstanding?: number;
	sweepIntervalMs?: number;
}

/** The per-request public key the envelope publishes. */
export function requestEncryptionPublicKey(record: IDfRequestRecord): Buffer {
	return getPublicKey(Buffer.from(record.encryptionPrivateKeyHex, 'hex'));
}

export class DirectFundingRequestStore {
	/** By receipt hash: the index the envelope field and an offer arrive on. */
	private byHash = new Map<string, IDfRequestRecord>();
	/** By request id: the index a sealed frame arrives on. */
	private byId = new Map<string, string>();
	/** By onion path secret: the index a blinded-path delivery arrives on. */
	private byPathSecret = new Map<string, string>();
	/** Payments received, by receipt hash. Outlives the records above. */
	private receivedByHash = new Map<string, IDfReceivedRecord>();
	/**
	 * The received set changed and the write did not land. Every later write
	 * retries it.
	 */
	private receivedUnsaved = false;
	/**
	 * Receipt hashes whose received record has not reached storage. Until it
	 * does, the paid request is not swept: its tombstone is then the only
	 * stored trace of the payment.
	 */
	private unsavedReceipts = new Set<string>();
	private sweepTimer: NodeJS.Timeout | null = null;
	private readonly ttlMs: number;
	private readonly maxOutstanding: number;
	private readonly sweepIntervalMs: number;

	constructor(
		private readonly deps: IDfRequestStoreDeps,
		config: IDfRequestStoreConfig = {}
	) {
		this.ttlMs = Math.min(
			config.requestTtlMs ?? DF_DEFAULT_REQUEST_TTL_MS,
			DF_MAX_REQUEST_TTL_MS
		);
		this.maxOutstanding = config.maxOutstanding ?? DF_DEFAULT_MAX_OUTSTANDING;
		this.sweepIntervalMs =
			config.sweepIntervalMs ?? DF_DEFAULT_SWEEP_INTERVAL_MS;
	}

	private now(): number {
		return this.deps.now ? this.deps.now() : Date.now();
	}

	// ─────────────── Lifecycle ───────────────

	/**
	 * Reload outstanding requests, dropping the expired ones no funding still
	 * needs (see `answersFor`), and rebuild both indexes. Returns how many came
	 * back. Call once, after the node's own storage restore.
	 *
	 * The received records come back first, and a paid request that has none
	 * (one paid before they were kept) is given its record here, before an
	 * expired one is dropped and takes the only trace of its payment with it.
	 */
	restore(): number {
		this.byHash.clear();
		this.byId.clear();
		this.byPathSecret.clear();
		this.restoreReceived();
		const raw = this.deps.storage?.loadWalletData(DF_REQUESTS_STORAGE_KEY);
		let parsed: unknown = [];
		try {
			parsed = raw ? JSON.parse(raw) : [];
		} catch {
			// Corrupt state runs from nothing rather than taking the node down;
			// the outstanding envelopes are lost either way, and refusing to
			// start would lose the wallet too.
		}
		const entries: IDfRequestRecord[] = [];
		let dropped = 0;
		let stripped = false;
		for (const entry of Array.isArray(parsed) ? parsed : []) {
			if (!isWellFormedRecord(entry)) {
				dropped++;
				continue;
			}
			// The strip comes FIRST: a row whose only claim on life is a marker
			// that did not come back intact has no funding to answer for.
			if (stripMalformedAttempt(entry)) stripped = true;
			this.receive(entry);
			entries.push(entry);
		}
		// Before anything is dropped below: an expired paid request goes only
		// once its payment's record is stored.
		if (this.receivedUnsaved) this.persistReceived();
		const now = this.now();
		for (const entry of entries) {
			if (
				!answersFor(entry, now) &&
				!this.unsavedReceipts.has(entry.receiptHash)
			) {
				dropped++;
				continue;
			}
			this.index(entry);
		}
		// Only rewrite when the set actually changed, so a restart with nothing
		// to drop does not touch storage at all.
		if (dropped > 0 || stripped) this.persist();
		return this.byHash.size;
	}

	/**
	 * Start the expiry sweep. A request that is never paid still holds a store
	 * slot and a path-secret index, and its secrets stay on disk, so expiry
	 * cannot wait for the next mint the way the fork's did.
	 */
	start(): void {
		if (this.sweepTimer) return;
		this.sweepTimer = setInterval(() => this.sweep(), this.sweepIntervalMs);
		this.sweepTimer.unref?.();
	}

	stop(): void {
		if (!this.sweepTimer) return;
		clearInterval(this.sweepTimer);
		this.sweepTimer = null;
	}

	/**
	 * Drop every expired record, save one still answering for a funding it left
	 * in flight. Returns how many went.
	 */
	sweep(): number {
		const now = this.now();
		// Received records past retention go here too, so a node that takes no
		// new payment still lets them go.
		if (this.pruneReceived()) this.receivedUnsaved = true;
		if (this.receivedUnsaved) this.persistReceived();
		let dropped = 0;
		for (const record of [...this.byHash.values()]) {
			// A paid request is its payment's only stored trace until the
			// received record lands.
			if (
				!answersFor(record, now) &&
				!this.unsavedReceipts.has(record.receiptHash)
			) {
				this.unindex(record);
				dropped++;
			}
		}
		if (dropped > 0) this.persist();
		return dropped;
	}

	// ─────────────── Minting ───────────────

	/**
	 * Mint one request: a fresh id, receipt preimage, encryption keypair and
	 * onion path secret, none of them reused across requests.
	 *
	 * Throws TOO_MANY_REQUESTS at the cap (cleanly, rather than by exhaustion:
	 * the fork had no cap at all and every mint persists a secret record), and
	 * NOT_PERSISTED when the write fails, because an envelope whose secrets did
	 * not reach storage must never be handed out.
	 *
	 * `amountSat` fixes the amount, and must be the same value the envelope is
	 * minted with. It is recorded here because this is the copy the receiver
	 * checks an arriving offer against; the envelope's is the payer's.
	 */
	mint(opts: { ttlMs?: number; amountSat?: bigint } = {}): IDfRequestRecord {
		this.sweep();
		if (this.byHash.size >= this.maxOutstanding) {
			throw new DirectFundingError(
				DirectFundingErrorCode.TOO_MANY_REQUESTS,
				`${this.byHash.size} direct-funding requests already outstanding`
			);
		}
		if (
			opts.amountSat !== undefined &&
			(opts.amountSat <= 0n || opts.amountSat > DF_MAX_AMOUNT_SAT)
		) {
			throw malformed(`amount_sat out of range: ${opts.amountSat}`);
		}
		const ttl = Math.min(opts.ttlMs ?? this.ttlMs, DF_MAX_REQUEST_TTL_MS);
		const preimage = randomBytes(DF_PREIMAGE_BYTES);
		const encryption = mintRequestEncryptionKeys();
		const record: IDfRequestRecord = {
			requestId: randomBytes(DF_REQUEST_ID_BYTES).toString('hex'),
			receiptHash: sha256(preimage).toString('hex'),
			preimageHex: preimage.toString('hex'),
			encryptionPrivateKeyHex: encryption.privateKey.toString('hex'),
			// Minted for every request whether or not an onion descriptor ends
			// up in the envelope: it is the index a blinded-path delivery
			// resolves on, and it must never be derivable from anything the
			// payer holds.
			onionPathSecretHex: randomBytes(DF_PATH_SECRET_BYTES).toString('hex'),
			expiresAt: this.now() + ttl,
			...(opts.amountSat !== undefined
				? { amountSat: opts.amountSat.toString() }
				: {})
		};
		this.index(record);
		if (!this.persist()) {
			this.unindex(record);
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'direct-funding request could not be persisted'
			);
		}
		return record;
	}

	// ─────────────── Lookups ───────────────

	/** By request id, or null when unknown or expired. */
	byRequestId(requestIdHex: string): IDfRequestRecord | null {
		const hash = this.byId.get(requestIdHex);
		return hash ? this.byReceiptHash(hash) : null;
	}

	/** By blinded-path secret, or null when unknown or expired. */
	byOnionPathSecret(pathSecretHex: string): IDfRequestRecord | null {
		const hash = this.byPathSecret.get(pathSecretHex);
		return hash ? this.byReceiptHash(hash) : null;
	}

	byReceiptHash(receiptHashHex: string): IDfRequestRecord | null {
		const record = this.byHash.get(receiptHashHex);
		if (!record) return null;
		return answersFor(record, this.now()) ? record : null;
	}

	/**
	 * The preimage an offer against this request is owed after broadcast. A
	 * tombstoned request still answers: a payer whose receipt frame was lost
	 * re-sends its offer and must be replayed the same receipt.
	 */
	receiptPreimage(receiptHashHex: string): string | null {
		return this.byReceiptHash(receiptHashHex)?.preimageHex ?? null;
	}

	/**
	 * Record that the receipt was revealed. The request is TOMBSTONED, not
	 * retired: the fork deleted it here, which threw away the encryption key,
	 * so a re-sent offer was dropped as unknown before the idempotent replay
	 * path was ever reached and the payer could never obtain its receipt.
	 * Effects stay single-use because 4C keys them on the offer session; what
	 * survives is the ability to answer.
	 *
	 * Throws NOT_PERSISTED when the tombstone does not reach storage, for the
	 * same reason mint does: a receipt revealed against a request that comes
	 * back looking unpaid is a paid request the next restart cannot recognise.
	 * The in-memory mark stands either way, so a caller that retries writes the
	 * whole set again rather than losing the reveal.
	 *
	 * The same call writes the request's received record (issue #1893), and
	 * throws NOT_PERSISTED when that write fails too: it is the only way a
	 * client finds out the request was paid once the record above is swept.
	 * It is written FIRST, because the tombstone clears the mark that holds the
	 * channel and the amount, and a failed write is retried by every later one
	 * while the paid request is kept from the sweep. `amountSat` is the paying
	 * offer's amount, when the caller still holds it.
	 */
	markReceiptRevealed(
		receiptHashHex: string,
		paidBy?: { offerIdHex: string; fundingTxidHex: string; amountSat?: string }
	): void {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record) return;
		if (record.revealedAt === undefined) record.revealedAt = this.now();
		// The FIRST payment's receipt stands: a later offer against a tombstoned
		// request is refused, so anything overwriting this would be answering a
		// replay with someone else's funding.
		if (paidBy && !record.paidBy) {
			// Before the mark is cleared below: the funding it holds is where the
			// channel and, on a recovery path, the amount come from.
			const funding = paidFunding(
				record,
				paidBy.offerIdHex,
				paidBy.fundingTxidHex
			);
			const amount = [paidBy.amountSat, funding?.amountSat].find(
				isPositiveDecimal
			);
			record.paidBy = {
				offerIdHex: paidBy.offerIdHex,
				fundingTxidHex: paidBy.fundingTxidHex,
				...(funding
					? { channelIdHex: funding.channelId, splice: funding.splice }
					: {}),
				...(amount !== undefined ? { amountSat: amount } : {})
			};
		}
		this.receive(record);
		// Written whenever there is one, not only when it is new, so a caller's
		// retry lands it.
		const kept =
			!this.receivedByHash.has(record.receiptHash) || this.persistReceived();
		// A funding that completed past its request's own expiry leaves a
		// tombstone the next sweep takes at once, and the payer has spent its coin
		// by then: a receipt frame lost on the way could never be replayed. The row
		// answers to the end of the hold that funding ran under, which is the
		// window the payer's lane was live in anyway (issue #644).
		const held = record.activeAttempt;
		if (held?.funding && record.expiresAt < held.expiresAt) {
			record.expiresAt = held.expiresAt;
		}
		record.activeAttempt = undefined;
		const tombstoned = this.persist();
		if (!tombstoned) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'direct-funding receipt tombstone could not be persisted'
			);
		}
		if (!kept) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'direct-funding received record could not be persisted'
			);
		}
	}

	isTombstoned(receiptHashHex: string): boolean {
		return this.byReceiptHash(receiptHashHex)?.revealedAt !== undefined;
	}

	/**
	 * The offer this request was paid by, or null. What a receiver restarted
	 * after the exchange answers a re-sent offer with: the in-memory session
	 * holding the recorded receipt is gone, and a bare tombstone would leave
	 * the payer with a spent coin and no proof of what it bought.
	 */
	paidOffer(
		receiptHashHex: string
	): { offerIdHex: string; fundingTxidHex: string } | null {
		const paid = this.byReceiptHash(receiptHashHex)?.paidBy;
		return paid
			? { offerIdHex: paid.offerIdHex, fundingTxidHex: paid.fundingTxidHex }
			: null;
	}

	// ─────────────── Received payments ───────────────

	/** Every payment received that is still kept, newest first. */
	received(): IDfReceivedRecord[] {
		return [...this.receivedByHash.values()]
			.sort((a, b) => b.paidAt - a.paidAt)
			.map((entry) => ({ ...entry }));
	}

	/** The payment a request was paid by, or null. Outlives the request. */
	receivedFor(receiptHashHex: string): IDfReceivedRecord | null {
		const entry = this.receivedByHash.get(receiptHashHex);
		return entry ? { ...entry } : null;
	}

	/**
	 * Mark the payments a reverted splice carried (issue #760). The payer spent
	 * its coin elsewhere and the channel is back on its old funding, so the
	 * request was not paid after all, whatever its receipt says. The record
	 * stays, REVERTED, so a client that showed the payment can take it back.
	 * Returns how many it marked. A mark whose write fails is retried by the
	 * next write, and the receiver checks again against the channel's own
	 * memory of the revert when it starts.
	 */
	markReceivedReverted(fundingTxidHex: string): number {
		const now = this.now();
		let marked = 0;
		for (const entry of this.receivedByHash.values()) {
			if (entry.fundingTxid !== fundingTxidHex) continue;
			if (entry.status === 'REVERTED') continue;
			entry.status = 'REVERTED';
			entry.updatedAt = now;
			marked++;
		}
		if (marked > 0) {
			this.receivedUnsaved = true;
			this.persistReceived();
		}
		return marked;
	}

	/**
	 * Funding attempts this request has spent, and the offer holding its one
	 * session right now. A LAPSED marker answers as none: the session it
	 * belonged to did not survive whatever ended it, and a crash must not lock
	 * a request for the rest of its life.
	 */
	attemptsFor(receiptHashHex: string): {
		attempts: number;
		activeOfferId?: string;
		/** The funding that attempt left in flight, when it got that far. */
		funding?: IDfAttemptFunding;
	} {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record) return { attempts: 0 };
		const active = record.activeAttempt;
		if (!active || active.expiresAt <= this.now()) {
			return { attempts: record.attempts ?? 0 };
		}
		return {
			attempts: record.attempts ?? 0,
			activeOfferId: active.offerIdHex,
			...(active.funding ? { funding: active.funding } : {})
		};
	}

	/**
	 * Name the funding an attempt negotiated, and hold the busy mark for as long
	 * as that funding can still complete.
	 *
	 * Written before the payer is asked to sign, because the window the sign
	 * request opens is exactly the one a crash strands a channel in: the
	 * negotiated transaction spends the payer's coin into a channel the peer
	 * already signed for, and only the payer's witness can finish it. Holding to
	 * the request's own expiry rather than the session TTL is what stops the
	 * request going free under a funding still waiting on that witness, and the
	 * record answers for the mark for as long as it stands, its own expiry
	 * included (issue #644).
	 *
	 * Reports whether the write landed. A false answer leaves the mark standing
	 * in memory, so the funding is still held for this process's life; what is
	 * lost is the binding a restart would have rebuilt from it.
	 */
	markAttemptFunding(
		receiptHashHex: string,
		offerIdHex: string,
		funding: IDfAttemptFunding,
		expiresAt: number
	): boolean {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record || record.activeAttempt?.offerIdHex !== offerIdHex)
			return false;
		record.activeAttempt.funding = funding;
		if (record.activeAttempt.expiresAt < expiresAt) {
			record.activeAttempt.expiresAt = expiresAt;
		}
		return this.persist();
	}

	/**
	 * Every request holding a funding in flight right now. What a restarting
	 * receiver re-takes its outpoint reservations from, so a coin already
	 * committed to one request's funding cannot be offered to another's.
	 */
	activeFundings(): Array<{
		receiptHash: string;
		offerIdHex: string;
		expiresAt: number;
		funding: IDfAttemptFunding;
	}> {
		const now = this.now();
		const out: Array<{
			receiptHash: string;
			offerIdHex: string;
			expiresAt: number;
			funding: IDfAttemptFunding;
		}> = [];
		for (const record of this.byHash.values()) {
			const active = record.activeAttempt;
			if (!active?.funding || active.expiresAt <= now) continue;
			out.push({
				receiptHash: record.receiptHash,
				offerIdHex: active.offerIdHex,
				expiresAt: active.expiresAt,
				funding: active.funding
			});
		}
		return out;
	}

	/**
	 * Fundings whose hold has run out on a request that is itself past its
	 * expiry: the rows the sweep will not take (issue #644).
	 *
	 * The store cannot retire one of these on its own. Only the receiver knows
	 * whether the channel the funding names can still be told to give it up, so
	 * it is handed the row and clears the mark with `endAttempt` when it has;
	 * the record then goes with the next sweep like any other expired one.
	 */
	lapsedFundings(): Array<{
		receiptHash: string;
		offerIdHex: string;
		funding: IDfAttemptFunding;
	}> {
		const now = this.now();
		const out: Array<{
			receiptHash: string;
			offerIdHex: string;
			funding: IDfAttemptFunding;
		}> = [];
		for (const record of this.byHash.values()) {
			const active = record.activeAttempt;
			if (!active?.funding) continue;
			if (active.expiresAt > now || record.expiresAt > now) continue;
			out.push({
				receiptHash: record.receiptHash,
				offerIdHex: active.offerIdHex,
				funding: active.funding
			});
		}
		return out;
	}

	/**
	 * Charge one attempt and mark the request busy. Durable, because the
	 * session it belongs to is not: a restart that forgot both would hand the
	 * duplicate offer that follows a fresh budget and a second channel session
	 * for a funding already in flight.
	 *
	 * A failed write is logged nowhere and does not throw, unlike mint's: the
	 * attempt is real either way, and refusing a payment over a storage hiccup
	 * costs more than the restart-crossing guard it loses.
	 *
	 * False means there is no live record to charge, which is the request
	 * expiring between an admission's checks and its insert. The caller must
	 * unwind rather than run a session nothing can mark busy: a request past its
	 * expiry answers every attempt question with zero, so two offers would
	 * otherwise each believe they hold its only funding session.
	 */
	beginAttempt(
		receiptHashHex: string,
		offerIdHex: string,
		slotExpiresAt: number
	): boolean {
		const record = this.byReceiptHash(receiptHashHex);
		// On the REQUEST'S own clock, not the record's: one still answering for a
		// funding it outlived its expiry for (issue #644) is past being payable,
		// and a fresh attempt would take the mark that funding is held by.
		if (!record || record.expiresAt <= this.now()) return false;
		record.attempts = (record.attempts ?? 0) + 1;
		record.activeAttempt = { offerIdHex, expiresAt: slotExpiresAt };
		this.persist();
		return true;
	}

	/**
	 * Hold the busy mark past the session that took it, for a funding the
	 * channel would not release: that funding can still complete on a late
	 * witness, so the request has not become free for another one. Extends only,
	 * and charges no second attempt.
	 */
	extendAttempt(
		receiptHashHex: string,
		offerIdHex: string,
		expiresAt: number
	): void {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record || record.activeAttempt?.offerIdHex !== offerIdHex) return;
		if (record.activeAttempt.expiresAt >= expiresAt) return;
		record.activeAttempt.expiresAt = expiresAt;
		this.persist();
	}

	/** Release the busy mark on a settled attempt. The COUNT stays charged. */
	endAttempt(receiptHashHex: string, offerIdHex: string): void {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record || record.activeAttempt?.offerIdHex !== offerIdHex) return;
		record.activeAttempt = undefined;
		this.persist();
	}

	/**
	 * The lane keys for an arriving frame, or null when this node did not mint
	 * the request it names. Null is the whole point: a frame sealed to an
	 * unknown request is dropped in SILENCE, with no reply and no log line a
	 * peer can provoke at will.
	 */
	laneKeysForFrame(
		frame: IDfWireFrame
	): { record: IDfRequestRecord; keys: IDfLaneKeys } | null {
		if (!frame.requestId || !frame.ephemeralPublicKey) return null;
		const record = this.byRequestId(frame.requestId.toString('hex'));
		if (!record) return null;
		return this.laneKeysFor(record, frame.ephemeralPublicKey);
	}

	/**
	 * The lane keys for a payer ephemeral key recorded earlier, or null when
	 * they cannot be derived. What a continuation frame arriving after a restart
	 * is opened with (issue #635): only the opening frame carries the ephemeral
	 * key, so the witness that follows one is unreadable without the copy the
	 * funding kept.
	 */
	laneKeysFor(
		record: IDfRequestRecord,
		ephemeralPublicKey: Buffer
	): { record: IDfRequestRecord; keys: IDfLaneKeys } | null {
		try {
			return {
				record,
				keys: receiverLaneKeys(
					Buffer.from(record.encryptionPrivateKeyHex, 'hex'),
					ephemeralPublicKey,
					Buffer.from(record.requestId, 'hex')
				)
			};
		} catch {
			// A malformed ephemeral key is a probe, not an event.
			return null;
		}
	}

	/**
	 * Drop a request that was never handed out, the mint's own unwind: an
	 * envelope that could not be built leaves a record holding secrets nothing
	 * will ever pay, and it would otherwise sit in the store until it expired.
	 *
	 * A record that has been touched by an offer is NEVER dropped here: the
	 * tombstone and the encryption key are what a payer whose receipt was lost
	 * replays against, and losing them costs it the proof of a payment it has
	 * already made.
	 */
	forget(receiptHashHex: string): boolean {
		const record = this.byHash.get(receiptHashHex);
		if (!record) return false;
		if (record.revealedAt !== undefined || record.attempts !== undefined) {
			return false;
		}
		this.unindex(record);
		this.persist();
		return true;
	}

	/** Live records, expired ones excluded. */
	list(): IDfRequestRecord[] {
		const now = this.now();
		return [...this.byHash.values()].filter((r) => r.expiresAt > now);
	}

	size(): number {
		return this.byHash.size;
	}

	// ─────────────── Internals ───────────────

	private index(record: IDfRequestRecord): void {
		this.byHash.set(record.receiptHash, record);
		this.byId.set(record.requestId, record.receiptHash);
		this.byPathSecret.set(record.onionPathSecretHex, record.receiptHash);
	}

	private unindex(record: IDfRequestRecord): void {
		this.byHash.delete(record.receiptHash);
		this.byId.delete(record.requestId);
		this.byPathSecret.delete(record.onionPathSecretHex);
	}

	/**
	 * Write the whole set. Reports whether it landed. A received set whose own
	 * write failed is retried with it, since no caller retries that one.
	 */
	private persist(): boolean {
		if (this.receivedUnsaved) this.persistReceived();
		if (!this.deps.storage) return true;
		try {
			this.deps.storage.saveWalletData(
				DF_REQUESTS_STORAGE_KEY,
				JSON.stringify([...this.byHash.values()])
			);
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * Add the received record for a paid request, once: the first payment's
	 * stands, as its receipt does. Reports whether it added one, which is then
	 * unsaved until a write lands it.
	 *
	 * The channel and the amount come from what the tombstone kept, then from
	 * the funding the paying offer's mark holds, when it still holds one (a
	 * mark held by any other offer describes another funding). The amount
	 * falls back to the one the request fixed.
	 */
	private receive(record: IDfRequestRecord): boolean {
		const paid = record.paidBy;
		if (!paid || this.receivedByHash.has(record.receiptHash)) return false;
		// Dated from the payment, so a record backfilled from an old tombstone
		// is held to the same window as one written at the time.
		const paidAt = record.revealedAt ?? this.now();
		if (this.now() - paidAt > DF_RECEIVED_RETENTION_MS) return false;
		const funding = paidFunding(record, paid.offerIdHex, paid.fundingTxidHex);
		const kept =
			typeof paid.channelIdHex === 'string' &&
			isHex(paid.channelIdHex, 32) &&
			typeof paid.splice === 'boolean'
				? { channelId: paid.channelIdHex, splice: paid.splice }
				: undefined;
		const channel =
			kept ??
			(funding
				? { channelId: funding.channelId, splice: funding.splice }
				: undefined);
		const amount = [paid.amountSat, funding?.amountSat, record.amountSat].find(
			isPositiveDecimal
		);
		this.evictReceived();
		this.receivedByHash.set(record.receiptHash, {
			receiptHash: record.receiptHash,
			requestId: record.requestId,
			offerId: paid.offerIdHex,
			fundingTxid: paid.fundingTxidHex,
			...(channel ?? {}),
			...(amount !== undefined ? { amountSat: amount } : {}),
			status: 'PAID',
			paidAt,
			updatedAt: paidAt
		});
		this.receivedUnsaved = true;
		this.unsavedReceipts.add(record.receiptHash);
		return true;
	}

	private restoreReceived(): void {
		this.receivedByHash.clear();
		this.receivedUnsaved = false;
		this.unsavedReceipts.clear();
		const raw = this.deps.storage?.loadWalletData(DF_RECEIVED_STORAGE_KEY);
		if (!raw) return;
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			// What is lost is bookkeeping, not money: the funding is in the channel
			// or it is not, and a request still held is given its record again.
			return;
		}
		if (!Array.isArray(parsed)) return;
		for (const entry of parsed) {
			if (isWellFormedReceived(entry)) {
				this.receivedByHash.set(entry.receiptHash, entry);
			}
		}
		if (this.pruneReceived()) this.receivedUnsaved = true;
	}

	/**
	 * Drop records not paid or changed within the retention window. Reports
	 * whether any went.
	 */
	private pruneReceived(): boolean {
		const now = this.now();
		let pruned = false;
		for (const entry of [...this.receivedByHash.values()]) {
			if (now - entry.updatedAt > DF_RECEIVED_RETENTION_MS) {
				this.receivedByHash.delete(entry.receiptHash);
				pruned = true;
			}
		}
		return pruned;
	}

	/**
	 * Drop records past retention, then the oldest while the set is at its
	 * ceiling, so the one about to be added fits.
	 */
	private evictReceived(): void {
		this.pruneReceived();
		if (this.receivedByHash.size < DF_MAX_RECEIVED_RECORDS) return;
		const oldest = [...this.receivedByHash.values()].sort(
			(a, b) => a.updatedAt - b.updatedAt
		);
		for (const entry of oldest) {
			if (this.receivedByHash.size < DF_MAX_RECEIVED_RECORDS) break;
			this.receivedByHash.delete(entry.receiptHash);
		}
	}

	/** Write every received record. Reports whether it landed. */
	private persistReceived(): boolean {
		let landed = true;
		if (this.deps.storage) {
			try {
				this.deps.storage.saveWalletData(
					DF_RECEIVED_STORAGE_KEY,
					JSON.stringify([...this.receivedByHash.values()])
				);
			} catch {
				landed = false;
			}
		}
		this.receivedUnsaved = !landed;
		if (landed) this.unsavedReceipts.clear();
		return landed;
	}
}

/**
 * Whether a record still answers, which is not the question of whether the
 * request it belongs to can still be paid.
 *
 * A record holding a funding in flight outlives its own expiry (issue #644).
 * That funding names a channel the peer has already signed for and only the
 * payer's witness can finish, and this row holds the only copy of the lane key
 * that witness can be opened on and of the preimage that acknowledges it: swept
 * on the request's clock, the channel can be completed by no route at all and
 * nothing retires it either. The mark is cleared when the funding settles, or
 * by the receiver when it gives the funding up, and the record goes with the
 * next sweep after that.
 *
 * A LIVE attempt counts before it has named a funding, because the negotiation
 * that names one can itself outlast the request: the binding is written only
 * when the transaction is final, and a row taken in that window refuses the
 * write and strands the same channel. The marker's own deadline bounds it, and
 * `beginAttempt` still judges the request's clock, so nothing here makes an
 * expired request payable again.
 */
function answersFor(record: IDfRequestRecord, now: number): boolean {
	if (record.expiresAt > now) return true;
	const active = record.activeAttempt;
	if (active === undefined) return false;
	return active.funding !== undefined || active.expiresAt > now;
}

function isHex(value: unknown, bytes: number): boolean {
	return (
		typeof value === 'string' &&
		value.length === bytes * 2 &&
		/^[0-9a-f]+$/i.test(value)
	);
}

/**
 * A persisted row is only usable if every secret in it is the right width:
 * a truncated key would be indexed and then fail deep inside an ECDH, on a
 * request a payer is already holding.
 */
function isWellFormedRecord(entry: unknown): entry is IDfRequestRecord {
	const r = entry as IDfRequestRecord | null;
	return (
		!!r &&
		isHex(r.requestId, DF_REQUEST_ID_BYTES) &&
		isHex(r.receiptHash, 32) &&
		isHex(r.preimageHex, DF_PREIMAGE_BYTES) &&
		isHex(r.encryptionPrivateKeyHex, 32) &&
		isHex(r.onionPathSecretHex, DF_PATH_SECRET_BYTES) &&
		typeof r.expiresAt === 'number' &&
		Number.isFinite(r.expiresAt) &&
		// A fixed amount that did not come back intact must not read as "any
		// amount will do": the record is dropped and the request goes unpayable,
		// which is the recoverable half of that choice.
		(r.amountSat === undefined || isPositiveDecimal(r.amountSat))
	);
}

/**
 * Drop an attempt marker that did not come back intact.
 *
 * It decides whether a second offer may fund this request at all, and through
 * the funding it names, which channel a re-sent offer is served from. A
 * half-restored marker would answer both with garbage, where no marker only
 * costs the request the guard until its next attempt takes one.
 */
function stripMalformedAttempt(record: IDfRequestRecord): boolean {
	const active = record.activeAttempt;
	if (active === undefined) return false;
	if (
		isHex(active.offerIdHex, DF_OFFER_ID_BYTES) &&
		typeof active.expiresAt === 'number' &&
		Number.isFinite(active.expiresAt) &&
		isWellFormedFunding(active.funding)
	) {
		return false;
	}
	record.activeAttempt = undefined;
	return true;
}

function isWellFormedFunding(funding: unknown): boolean {
	if (funding === undefined) return true;
	const f = funding as IDfAttemptFunding | null;
	return (
		!!f &&
		typeof f.outpoint === 'string' &&
		/^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/i.test(f.outpoint) &&
		isHex(f.channelId, 32) &&
		typeof f.splice === 'boolean' &&
		isHex(f.contentHash, 32) &&
		isHex(f.payerEphemeralKey, DF_NODE_ID_BYTES) &&
		(f.fundingTxid === undefined || isHex(f.fundingTxid, 32))
	);
}

/**
 * A received record is only shown if it came back whole. An amount that did
 * not is dropped with the row rather than shown as some other figure.
 */
/**
 * The funding the paying offer's mark still holds, if it holds one for that
 * funding. A mark held by any other offer describes another funding.
 */
function paidFunding(
	record: IDfRequestRecord,
	offerIdHex: string,
	fundingTxidHex: string
): IDfAttemptFunding | undefined {
	const active = record.activeAttempt;
	if (active?.offerIdHex !== offerIdHex || !active.funding) return undefined;
	const txid = active.funding.fundingTxid;
	return txid === undefined || txid === fundingTxidHex
		? active.funding
		: undefined;
}

function isWellFormedReceived(entry: unknown): entry is IDfReceivedRecord {
	const r = entry as IDfReceivedRecord | null;
	return (
		!!r &&
		isHex(r.receiptHash, 32) &&
		isHex(r.requestId, DF_REQUEST_ID_BYTES) &&
		isHex(r.offerId, DF_OFFER_ID_BYTES) &&
		isHex(r.fundingTxid, 32) &&
		(r.channelId === undefined || isHex(r.channelId, 32)) &&
		(r.splice === undefined || typeof r.splice === 'boolean') &&
		(r.amountSat === undefined || isPositiveDecimal(r.amountSat)) &&
		(r.status === 'PAID' || r.status === 'REVERTED') &&
		Number.isFinite(r.paidAt) &&
		Number.isFinite(r.updatedAt)
	);
}

function isPositiveDecimal(value: unknown): value is string {
	if (typeof value !== 'string' || !/^[1-9][0-9]{0,17}$/.test(value)) {
		return false;
	}
	return BigInt(value) <= DF_MAX_AMOUNT_SAT;
}
