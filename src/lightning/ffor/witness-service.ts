/**
 * The receipt witness W (spec section 9.6): provisioning, retrieval, close
 * and retention over the Appendix F messages, on the durable ledger of
 * witness-ledger.ts. Section 9.6.5's store-before-propagate hook lives on
 * the node's forward path and calls into `interceptDownstreamFulfil` here.
 *
 * Authorization is by the mailbox's fetch_key, never the Noise peer id; a
 * witness never learns who R is. Unknown mailboxes answer exactly like empty
 * ones, so probing learns nothing.
 */

import crypto from 'crypto';
import { sign } from '../crypto/ecdh';
import { computeHAct, computeHBook, decodeVoucherBook } from './transcript';
import { sealRecordBody } from './witness-crypto';
import {
	FF_WITNESS_ACK_TYPE,
	FF_WITNESS_BARRIER_MS,
	FF_WITNESS_CLOSE_ACK_TYPE,
	FF_WITNESS_CLOSE_TYPE,
	FF_WITNESS_FETCH_RESP_TYPE,
	FF_WITNESS_FETCH_TYPE,
	FF_WITNESS_FLAG_UNBARRIERED,
	FF_WITNESS_PROFILE_DR,
	FF_WITNESS_PROVISION_TYPE,
	FF_WITNESS_REQUEST_ID_LEN,
	FF_WITNESS_RETENTION_MARGIN_BLOCKS,
	FF_WITNESS_VERSION,
	IFforWitnessRecord,
	IFforWitnessRecordHeader,
	FF_WITNESS_FETCH_PAGE_BYTES
} from './witness-types';
import {
	decodeRecord,
	decodeWitnessClose,
	decodeWitnessFetch,
	decodeWitnessProvision,
	encodeRecord,
	encodeRecordBody,
	encodeRecordHeader,
	encodeWitnessAck,
	encodeWitnessCloseAck,
	encodeWitnessFetchResp,
	recordAad,
	recordDigest,
	termsHash,
	verifyManifest,
	verifyWitnessClose,
	verifyWitnessFetch
} from './witness-messages';
import {
	FF_WITNESS_RECORD_RESERVE_BYTES,
	FforWitnessLedger,
	IFforWitnessEntry,
	IFforWitnessMailboxRecord
} from './witness-ledger';

export interface IFforWitnessConfig {
	enabled: boolean;
	/** Live mailboxes this witness will hold (default 64). */
	maxMailboxes?: number;
	/** Bytes it will reserve across them (default 8 MiB). */
	maxBytes?: number;
	/** Section 9.6.5 wall-clock bound on the barrier (default 30 s). */
	barrierMs?: number;
	/**
	 * Blocks before an incoming HTLC's expiry at which W propagates a held
	 * fulfil regardless. The node defaults it to one block past its own
	 * claim-and-force-close buffer, so the barrier always releases before
	 * the node closes the channel to claim the HTLC on-chain itself.
	 */
	safetyDelta?: number;
	/**
	 * Record bytes one ff_witness_fetch_resp carries at most (default
	 * FF_WITNESS_FETCH_PAGE_BYTES); a mailbox holding more answers in pages.
	 */
	fetchPageBytes?: number;
}

/** One downstream fulfil for an outgoing HTLC, as the node sees it. */
export interface IFforWitnessFulfil {
	/** "outChannelIdHex:offered-<id>", the node's forward key. */
	outKey: string;
	preimage: Buffer;
	paymentHash: Buffer;
	amountInMsat: bigint;
	amountOutMsat: bigint;
	outgoingCltv: number;
	incomingCltvExpiry: number;
}

export type FforWitnessIntercept = 'none' | 'recorded' | 'held';

export interface IFforWitnessDeps {
	ledger: FforWitnessLedger;
	nodePrivkey: Buffer;
	nodeId: Buffer;
	currentHeight: () => number;
	send: (peer: string, type: number, payload: Buffer) => void;
	log: (action: string, data: Record<string, unknown>) => void;
	emit: (event: string, data: unknown) => void;
	/**
	 * Propagate a fulfil the service held (section 9.6.5 step 5): the node
	 * settles the forward upstream now, whatever the record's state.
	 */
	release?: (
		fulfil: IFforWitnessFulfil,
		reason: 'recorded' | 'deadline'
	) => void;
}

interface IPendingBarrier {
	fulfil: IFforWitnessFulfil;
	mailboxIdHex: string;
	k: number;
	released: boolean;
	/** Set when the deadline propagated before the record landed. */
	unbarriered: boolean;
	wallTimer: NodeJS.Timeout | null;
	retryTimer: NodeJS.Timeout | null;
	cltvDeadline: number;
}

const DEFAULT_MAX_MAILBOXES = 64;
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;

export class FforWitnessService {
	readonly maxMailboxes: number;
	readonly maxBytes: number;
	readonly barrierMs: number;
	readonly safetyDelta: number;
	readonly fetchPageBytes: number;

	constructor(
		cfg: IFforWitnessConfig,
		private readonly deps: IFforWitnessDeps
	) {
		this.maxMailboxes = cfg.maxMailboxes ?? DEFAULT_MAX_MAILBOXES;
		this.maxBytes = cfg.maxBytes ?? DEFAULT_MAX_BYTES;
		this.barrierMs = cfg.barrierMs ?? FF_WITNESS_BARRIER_MS;
		this.safetyDelta = cfg.safetyDelta ?? 6;
		this.fetchPageBytes = Math.max(
			1,
			cfg.fetchPageBytes ?? FF_WITNESS_FETCH_PAGE_BYTES
		);
	}

	/** Fulfils held behind the barrier, by outKey. */
	private readonly pending = new Map<string, IPendingBarrier>();

	get ledger(): FforWitnessLedger {
		return this.deps.ledger;
	}

	// ── Recording: store before you propagate (section 9.6.5) ─────────

	/**
	 * A downstream fulfil reached this node for an outgoing HTLC. When the
	 * hash is in a live mailbox, the record is built, encrypted to R and
	 * committed durably BEFORE the caller may propagate the fulfil upstream.
	 *
	 * `none`: not a delegated fulfil, ordinary forwarding rules apply.
	 * `recorded`: the record is on disk (or already was); propagate now.
	 * `held`: the store refused; the node must NOT propagate until `release`
	 * is called, which happens when the write lands or at the bounded
	 * deadline (the wall-clock bound, or the incoming HTLC's expiry less the
	 * safety delta), whichever is first. A record written after a deadline
	 * release carries the `unbarriered` flag.
	 */
	interceptDownstreamFulfil(fulfil: IFforWitnessFulfil): FforWitnessIntercept {
		const hashHex = fulfil.paymentHash.toString('hex');
		const hit = this.deps.ledger.byHash(hashHex);
		if (!hit || hit.mailbox.state === 'CLOSED') return 'none';
		const t = crypto.createHash('sha256').update(fulfil.preimage).digest();
		if (!t.equals(fulfil.paymentHash)) return 'none';
		const already = this.pending.get(fulfil.outKey);
		if (already && !already.released) return 'held';
		if (this.deps.ledger.record(hit.mailbox.id, hit.k)) {
			// Idempotent: a replayed downstream fulfil creates no second record.
			return 'recorded';
		}
		if (this.tryStore(hit.mailbox, hit.k, fulfil, false)) return 'recorded';
		// The store refused: hold, retry, and bound the hold.
		const barrier: IPendingBarrier = {
			fulfil,
			mailboxIdHex: hit.mailbox.id,
			k: hit.k,
			released: false,
			unbarriered: false,
			wallTimer: null,
			retryTimer: null,
			cltvDeadline: fulfil.incomingCltvExpiry - this.safetyDelta
		};
		this.pending.set(fulfil.outKey, barrier);
		barrier.wallTimer = setTimeout(
			() => this.releaseBarrier(fulfil.outKey, 'deadline'),
			this.barrierMs
		);
		barrier.wallTimer.unref?.();
		this.scheduleRetry(barrier);
		this.deps.log('ffor_witness_record_held', {
			outKey: fulfil.outKey,
			mailboxId: hit.mailbox.id,
			k: hit.k,
			cltvDeadline: barrier.cltvDeadline
		});
		if (this.deps.currentHeight() >= barrier.cltvDeadline) {
			this.releaseBarrier(fulfil.outKey, 'deadline');
			return 'recorded';
		}
		return 'held';
	}

	/** Whether a forward is held behind the barrier right now. */
	isHeld(outKey: string): boolean {
		const b = this.pending.get(outKey);
		return b !== undefined && !b.released;
	}

	private scheduleRetry(barrier: IPendingBarrier): void {
		barrier.retryTimer = setTimeout(() => {
			barrier.retryTimer = null;
			const mailbox = this.deps.ledger.mailbox(barrier.mailboxIdHex);
			if (!mailbox || mailbox.state === 'EXPIRED') {
				this.pending.delete(barrier.fulfil.outKey);
				return;
			}
			if (
				this.tryStore(mailbox, barrier.k, barrier.fulfil, barrier.unbarriered)
			) {
				if (!barrier.released) {
					this.releaseBarrier(barrier.fulfil.outKey, 'recorded');
				} else {
					this.pending.delete(barrier.fulfil.outKey);
				}
				return;
			}
			this.scheduleRetry(barrier);
		}, 1000);
		barrier.retryTimer.unref?.();
	}

	private releaseBarrier(
		outKey: string,
		reason: 'recorded' | 'deadline'
	): void {
		const barrier = this.pending.get(outKey);
		if (!barrier || barrier.released) return;
		barrier.released = true;
		if (barrier.wallTimer) clearTimeout(barrier.wallTimer);
		barrier.wallTimer = null;
		if (reason === 'deadline') {
			// Section 9.6.5: propagate anyway, keep trying to store, and mark
			// the record unbarriered when it does land.
			barrier.unbarriered = true;
			this.deps.log('ffor_witness_barrier_deadline', {
				outKey,
				mailboxId: barrier.mailboxIdHex,
				k: barrier.k
			});
		} else {
			this.pending.delete(outKey);
		}
		this.deps.emit('ffor:witness-released', {
			outKey,
			mailboxId: Buffer.from(barrier.mailboxIdHex, 'hex'),
			k: barrier.k,
			reason
		});
		this.deps.release?.(barrier.fulfil, reason);
	}

	/** Build, seal, sign and commit the record; false when the store refused. */
	private tryStore(
		mailbox: IFforWitnessMailboxRecord,
		k: number,
		fulfil: IFforWitnessFulfil,
		unbarriered: boolean
	): boolean {
		const entry = mailbox.entries[k - 1];
		const body = encodeRecordBody({
			epochId: Buffer.from(mailbox.epochIdHex, 'hex'),
			k,
			t: fulfil.preimage,
			hK: fulfil.paymentHash,
			dK: BigInt(entry.amountMsat),
			tExp: entry.tExp,
			d: entry.d,
			amountInMsat: fulfil.amountInMsat,
			amountOutMsat: fulfil.amountOutMsat,
			outgoingCltv: fulfil.outgoingCltv,
			observedUnixTime: BigInt(Date.now())
		});
		const header: IFforWitnessRecordHeader = {
			version: FF_WITNESS_VERSION,
			profile: FF_WITNESS_PROFILE_DR,
			mailboxId: Buffer.from(mailbox.id, 'hex'),
			recordId: crypto.randomBytes(32),
			k,
			hAct: Buffer.from(mailbox.hActHex, 'hex'),
			termsHash: Buffer.from(entry.termsHashHex, 'hex'),
			witnessNodeId: this.deps.nodeId,
			encPubkey: Buffer.from(mailbox.encPubkeyHex, 'hex'),
			recordedHeight: this.deps.currentHeight(),
			flags: unbarriered ? FF_WITNESS_FLAG_UNBARRIERED : 0,
			ciphertextHash: Buffer.alloc(32)
		};
		const ciphertext = sealRecordBody(
			header.encPubkey,
			recordAad(header),
			body
		);
		header.ciphertextHash = crypto
			.createHash('sha256')
			.update(ciphertext)
			.digest();
		const record: IFforWitnessRecord = {
			header,
			witnessSig: sign(
				recordDigest(encodeRecordHeader(header)),
				this.deps.nodePrivkey
			),
			ciphertext,
			receipts: []
		};
		const result = this.deps.ledger.insertRecord({
			id: header.recordId.toString('hex'),
			mailboxIdHex: mailbox.id,
			k,
			recordHex: encodeRecord(record).toString('hex'),
			unbarriered,
			outKey: fulfil.outKey,
			recordedHeight: header.recordedHeight,
			receiptsPending: false
		});
		if (result.outcome === 'applied' || result.outcome === 'stale') {
			this.deps.log('ffor_witness_recorded', {
				mailboxId: mailbox.id,
				k,
				outKey: fulfil.outKey,
				unbarriered
			});
			this.deps.emit('ffor:witness-recorded', {
				mailboxId: Buffer.from(mailbox.id, 'hex'),
				k,
				outKey: fulfil.outKey,
				unbarriered
			});
			return true;
		}
		this.deps.log('ffor_witness_record_store_failed', {
			mailboxId: mailbox.id,
			k,
			outcome: result.outcome
		});
		return false;
	}

	/** A request of the witness lane; true when this service consumed it. */
	handleMessage(peer: string, type: number, payload: Buffer): boolean {
		switch (type) {
			case FF_WITNESS_PROVISION_TYPE:
				this.handleProvision(peer, payload);
				return true;
			case FF_WITNESS_FETCH_TYPE:
				this.handleFetch(peer, payload);
				return true;
			case FF_WITNESS_CLOSE_TYPE:
				this.handleClose(peer, payload);
				return true;
			default:
				return false;
		}
	}

	// ── Provisioning (section 9.6.4) ──────────────────────────────────

	private handleProvision(peer: string, payload: Buffer): void {
		if (payload.length < FF_WITNESS_REQUEST_ID_LEN) {
			this.deps.log('ffor_witness_provision_undecodable', { peer });
			return;
		}
		const requestId = Buffer.from(
			payload.subarray(0, FF_WITNESS_REQUEST_ID_LEN)
		);
		const refuse = (error: string): void => {
			this.deps.log('ffor_witness_provision_refused', { peer, error });
			this.deps.emit('ffor:witness-refused', { peer, reason: error });
			this.deps.send(
				peer,
				FF_WITNESS_ACK_TYPE,
				encodeWitnessAck({ requestId, ok: false, error })
			);
		};
		let decoded: ReturnType<typeof decodeWitnessProvision>;
		try {
			decoded = decodeWitnessProvision(payload);
		} catch (err) {
			refuse(`undecodable manifest: ${(err as Error).message}`);
			return;
		}
		const { manifest, manifestWire } = decoded;
		if (!verifyManifest(manifestWire, manifest)) {
			refuse('manifest signature invalid');
			return;
		}
		if (manifest.version !== FF_WITNESS_VERSION) {
			refuse(`manifest version ${manifest.version} not supported`);
			return;
		}
		if (manifest.profile !== FF_WITNESS_PROFILE_DR) {
			refuse(`profile ${manifest.profile} not supported`);
			return;
		}
		const mailboxIdHex = manifest.mailboxId.toString('hex');
		const existing = this.deps.ledger.mailbox(mailboxIdHex);
		if (existing) {
			// Byte-identical re-provision is idempotent; anything else is
			// somebody trying to rewrite a mailbox they may not own.
			if (existing.manifestHex === manifestWire.toString('hex')) {
				this.ack(peer, requestId, existing.retentionUntil);
				return;
			}
			refuse('mailbox already provisioned with a different manifest');
			return;
		}
		// The book, and the H_act it must reproduce.
		let entries: IFforWitnessEntry[];
		let hBook: Buffer;
		let tExp: number;
		let epochIdHex: string;
		try {
			const book = decodeVoucherBook(manifest.book);
			epochIdHex = book.epochId.toString('hex');
			if (book.entries.length === 0) throw new Error('book has no entries');
			const seen = new Set<string>();
			tExp = book.entries[0].voucherExpiry;
			const d = book.entries[0].settlementDeadline;
			entries = book.entries.map((e, i) => {
				if (e.k !== i + 1) throw new Error('book slots are not 1..K in order');
				const hex = e.paymentHash.toString('hex');
				if (seen.has(hex)) throw new Error('book repeats a hash');
				seen.add(hex);
				if (e.amountMsat <= 0n) throw new Error('book entry has no amount');
				if (e.voucherExpiry !== tExp || e.settlementDeadline !== d) {
					throw new Error('book entries disagree on T_exp or D');
				}
				return {
					k: e.k,
					hashHex: hex,
					amountMsat: e.amountMsat.toString(),
					tExp: e.voucherExpiry,
					d: e.settlementDeadline,
					sHtlcId: e.sHtlcId.toString(),
					termsHashHex: termsHash(e).toString('hex')
				};
			});
			hBook = computeHBook(manifest.book);
		} catch (err) {
			refuse(`inconsistent book: ${(err as Error).message}`);
			return;
		}
		const hAct = computeHAct(
			manifest.tSetup,
			hBook,
			manifest.hCommit,
			manifest.epochStartHeight
		);
		if (!hAct.equals(manifest.hAct)) {
			refuse('activation hash does not match the book');
			return;
		}
		if (manifest.retentionUntil < tExp + FF_WITNESS_RETENTION_MARGIN_BLOCKS) {
			refuse('retention_until is under T_exp + 144');
			return;
		}
		if (manifest.minReceipts > 0) {
			// Guardian receipts (Appendix F.4) need a journaled record store;
			// until then the honest answer is a refusal, not a silent 0.
			refuse('guardian receipts are not offered by this witness');
			return;
		}
		// Every hash must be new to this witness: one mailbox per hash, or a
		// record could be served under the wrong epoch.
		for (const e of entries) {
			if (this.deps.ledger.byHash(e.hashHex)) {
				refuse('a book hash is already held for another mailbox');
				return;
			}
		}
		const occupancy = this.deps.ledger.occupancy();
		const reserve = entries.length * FF_WITNESS_RECORD_RESERVE_BYTES;
		if (
			occupancy.mailboxes >= this.maxMailboxes ||
			occupancy.reservedBytes + reserve > this.maxBytes
		) {
			refuse('cannot reserve');
			return;
		}
		const result = this.deps.ledger.provision({
			id: mailboxIdHex,
			manifestHex: manifestWire.toString('hex'),
			epochIdHex,
			hActHex: manifest.hAct.toString('hex'),
			hBookHex: hBook.toString('hex'),
			tSetupHex: manifest.tSetup.toString('hex'),
			hCommitHex: manifest.hCommit.toString('hex'),
			epochStartHeight: manifest.epochStartHeight,
			fetchPubkeyHex: manifest.fetchPubkey.toString('hex'),
			encPubkeyHex: manifest.encPubkey.toString('hex'),
			retentionUntil: manifest.retentionUntil,
			minReceipts: manifest.minReceipts,
			entries,
			reservedBytes: reserve
		});
		if (result.outcome !== 'applied') {
			refuse(`cannot reserve: store ${result.outcome}`);
			return;
		}
		this.deps.log('ffor_witness_provisioned', {
			mailboxId: mailboxIdHex,
			slots: entries.length,
			retentionUntil: manifest.retentionUntil
		});
		this.deps.emit('ffor:witness-provisioned', {
			mailboxId: manifest.mailboxId,
			slots: entries.length,
			retentionUntil: manifest.retentionUntil,
			peer
		});
		this.ack(peer, requestId, manifest.retentionUntil);
	}

	private ack(peer: string, requestId: Buffer, retentionUntil: number): void {
		this.deps.send(
			peer,
			FF_WITNESS_ACK_TYPE,
			encodeWitnessAck({
				requestId,
				ok: true,
				witnessNodeId: this.deps.nodeId,
				retentionUntil
			})
		);
	}

	// ── Retrieval and close (section 9.6.6) ───────────────────────────

	private handleFetch(peer: string, payload: Buffer): void {
		if (payload.length < FF_WITNESS_REQUEST_ID_LEN) return;
		const requestId = Buffer.from(
			payload.subarray(0, FF_WITNESS_REQUEST_ID_LEN)
		);
		const empty = (): void => {
			this.deps.send(
				peer,
				FF_WITNESS_FETCH_RESP_TYPE,
				encodeWitnessFetchResp({ requestId, ok: true, records: [] })
			);
		};
		let msg: ReturnType<typeof decodeWitnessFetch>;
		try {
			msg = decodeWitnessFetch(payload);
		} catch {
			empty();
			return;
		}
		const mailboxIdHex = msg.mailboxId.toString('hex');
		const mailbox = this.deps.ledger.mailbox(mailboxIdHex);
		// An unknown mailbox, a bad signature and a replayed nonce all answer
		// exactly like an empty mailbox (F.1): nothing to learn by probing.
		if (!mailbox || mailbox.state === 'EXPIRED') {
			empty();
			return;
		}
		if (!verifyWitnessFetch(msg, Buffer.from(mailbox.fetchPubkeyHex, 'hex'))) {
			this.deps.log('ffor_witness_fetch_unauthorized', {
				mailboxId: mailboxIdHex
			});
			empty();
			return;
		}
		if (
			this.deps.ledger.acceptNonce(mailboxIdHex, msg.nonce.toString('hex')) !==
			'accepted'
		) {
			this.deps.log('ffor_witness_fetch_replayed', { mailboxId: mailboxIdHex });
			empty();
			return;
		}
		// F.1 paging: records above after_k in ascending k, as many as fit
		// the page and never fewer than one, and the last k served as
		// next_after_k while any remain.
		const afterK = msg.afterK ?? 0;
		const records: IFforWitnessRecord[] = [];
		let bytes = 0;
		let lastK = afterK;
		let nextAfterK: number | undefined;
		for (const row of this.deps.ledger.listRecords(mailboxIdHex)) {
			if (row.k <= afterK) continue;
			let rec: IFforWitnessRecord;
			try {
				rec = decodeRecord(Buffer.from(row.recordHex, 'hex'));
			} catch {
				this.deps.log('ffor_witness_record_corrupt', {
					mailboxId: mailboxIdHex,
					k: row.k
				});
				continue;
			}
			const len = row.recordHex.length / 2 + 2;
			if (records.length > 0 && bytes + len > this.fetchPageBytes) {
				nextAfterK = lastK;
				break;
			}
			records.push(rec);
			bytes += len;
			lastK = row.k;
		}
		this.deps.log('ffor_witness_fetched', {
			mailboxId: mailboxIdHex,
			afterK,
			records: records.length,
			more: nextAfterK !== undefined
		});
		this.deps.send(
			peer,
			FF_WITNESS_FETCH_RESP_TYPE,
			encodeWitnessFetchResp({
				requestId,
				ok: true,
				records,
				...(nextAfterK !== undefined ? { nextAfterK } : {})
			})
		);
	}

	private handleClose(peer: string, payload: Buffer): void {
		if (payload.length < FF_WITNESS_REQUEST_ID_LEN) return;
		const requestId = Buffer.from(
			payload.subarray(0, FF_WITNESS_REQUEST_ID_LEN)
		);
		const answer = (ok: boolean, held: number): void => {
			this.deps.send(
				peer,
				FF_WITNESS_CLOSE_ACK_TYPE,
				encodeWitnessCloseAck({ requestId, ok, numRecordsHeld: held })
			);
		};
		let msg: ReturnType<typeof decodeWitnessClose>;
		try {
			msg = decodeWitnessClose(payload);
		} catch {
			answer(false, 0);
			return;
		}
		const mailboxIdHex = msg.mailboxId.toString('hex');
		const mailbox = this.deps.ledger.mailbox(mailboxIdHex);
		if (
			!mailbox ||
			mailbox.state === 'EXPIRED' ||
			!verifyWitnessClose(msg, Buffer.from(mailbox.fetchPubkeyHex, 'hex')) ||
			msg.hAct.toString('hex') !== mailbox.hActHex ||
			msg.numSlots !== mailbox.entries.length
		) {
			answer(false, 0);
			return;
		}
		if (
			this.deps.ledger.acceptNonce(mailboxIdHex, msg.nonce.toString('hex')) !==
			'accepted'
		) {
			answer(false, 0);
			return;
		}
		const result = this.deps.ledger.close(
			mailboxIdHex,
			msg.settled.toString('hex')
		);
		if (result.outcome !== 'applied') {
			answer(false, 0);
			return;
		}
		const held = this.deps.ledger.listRecords(mailboxIdHex).length;
		this.deps.log('ffor_witness_closed', { mailboxId: mailboxIdHex, held });
		this.deps.emit('ffor:witness-closed', { mailboxId: msg.mailboxId, held });
		answer(true, held);
	}

	// ── Retention (section 9.6.6, 9.6.7) ──────────────────────────────

	onBlock(height: number): void {
		// The CLTV arm of the barrier (section 9.6.5): never past the incoming
		// HTLC's expiry less the safety delta.
		for (const [outKey, b] of this.pending) {
			if (!b.released && height >= b.cltvDeadline) {
				this.releaseBarrier(outKey, 'deadline');
			}
		}
		for (const m of this.deps.ledger.listMailboxes()) {
			if (m.state === 'EXPIRED') continue;
			if (m.retentionUntil < height) {
				const result = this.deps.ledger.expire(m.id);
				if (result.outcome === 'applied') {
					this.deps.log('ffor_witness_expired', { mailboxId: m.id });
					this.deps.emit('ffor:witness-expired', {
						mailboxId: Buffer.from(m.id, 'hex')
					});
				}
			}
		}
	}

	/** For operators and tests. */
	listMailboxes(): IFforWitnessMailboxRecord[] {
		return this.deps.ledger.listMailboxes();
	}

	static freshRequestId(): Buffer {
		return crypto.randomBytes(FF_WITNESS_REQUEST_ID_LEN);
	}
}
