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

import crypto from 'crypto';
import {
	IDfLaneKeys,
	IDfWireFrame,
	mintRequestEncryptionKeys,
	receiverLaneKeys
} from './frames';
import { getPublicKey } from '../crypto/ecdh';
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
	IDfAttemptFunding,
	IDfRequestRecord,
	malformed
} from './types';

/** Wallet-data key holding the whole outstanding set. */
export const DF_REQUESTS_STORAGE_KEY = 'df:requests';

/** Requests one node may have outstanding at once, each holding secrets. */
export const DF_DEFAULT_MAX_OUTSTANDING = 256;

/** How often the expiry sweep runs once `start()` has been called. */
export const DF_DEFAULT_SWEEP_INTERVAL_MS = 60_000;

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
	 */
	restore(): number {
		this.byHash.clear();
		this.byId.clear();
		this.byPathSecret.clear();
		const raw = this.deps.storage?.loadWalletData(DF_REQUESTS_STORAGE_KEY);
		if (!raw) return 0;
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			// Corrupt state runs from nothing rather than taking the node down;
			// the outstanding envelopes are lost either way, and refusing to
			// start would lose the wallet too.
			return 0;
		}
		if (!Array.isArray(parsed)) return 0;
		const now = this.now();
		let dropped = 0;
		let stripped = false;
		for (const entry of parsed as IDfRequestRecord[]) {
			if (!isWellFormedRecord(entry)) {
				dropped++;
				continue;
			}
			// The strip comes FIRST: a row whose only claim on life is a marker
			// that did not come back intact has no funding to answer for.
			if (stripMalformedAttempt(entry)) stripped = true;
			if (!answersFor(entry, now)) {
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
		let dropped = 0;
		for (const record of [...this.byHash.values()]) {
			if (!answersFor(record, now)) {
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
		const preimage = crypto.randomBytes(DF_PREIMAGE_BYTES);
		const encryption = mintRequestEncryptionKeys();
		const record: IDfRequestRecord = {
			requestId: crypto.randomBytes(DF_REQUEST_ID_BYTES).toString('hex'),
			receiptHash: crypto.createHash('sha256').update(preimage).digest('hex'),
			preimageHex: preimage.toString('hex'),
			encryptionPrivateKeyHex: encryption.privateKey.toString('hex'),
			// Minted for every request whether or not an onion descriptor ends
			// up in the envelope: it is the index a blinded-path delivery
			// resolves on, and it must never be derivable from anything the
			// payer holds.
			onionPathSecretHex: crypto
				.randomBytes(DF_PATH_SECRET_BYTES)
				.toString('hex'),
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
	 */
	markReceiptRevealed(
		receiptHashHex: string,
		paidBy?: { offerIdHex: string; fundingTxidHex: string }
	): void {
		const record = this.byReceiptHash(receiptHashHex);
		if (!record) return;
		if (record.revealedAt === undefined) record.revealedAt = this.now();
		// The FIRST payment's receipt stands: a later offer against a tombstoned
		// request is refused, so anything overwriting this would be answering a
		// replay with someone else's funding.
		if (paidBy && !record.paidBy) record.paidBy = paidBy;
		record.activeAttempt = undefined;
		if (!this.persist()) {
			throw new DirectFundingError(
				DirectFundingErrorCode.NOT_PERSISTED,
				'direct-funding receipt tombstone could not be persisted'
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
		return this.byReceiptHash(receiptHashHex)?.paidBy ?? null;
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

	/** Write the whole set. Reports whether it landed. */
	private persist(): boolean {
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
 */
function answersFor(record: IDfRequestRecord, now: number): boolean {
	return record.expiresAt > now || record.activeAttempt?.funding !== undefined;
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
		isHex(f.payerEphemeralKey, DF_NODE_ID_BYTES)
	);
}

function isPositiveDecimal(value: unknown): boolean {
	if (typeof value !== 'string' || !/^[1-9][0-9]{0,17}$/.test(value)) {
		return false;
	}
	return BigInt(value) <= DF_MAX_AMOUNT_SAT;
}
