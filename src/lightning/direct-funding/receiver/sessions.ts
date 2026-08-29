/**
 * Per-instance receiver state: offer sessions and outpoint reservations
 * (issue #612).
 *
 * Both were MODULE-level maps in the fork, shared by every node in the
 * process, pruned only from inside the offer handler and capped only by an
 * in-flight counter that was itself off by one (defects D15, D16). Here they
 * belong to one engine instance, a timer sweeps them whether or not offers are
 * arriving, and the map itself has a ceiling.
 *
 * The per-request attempt budget is deliberately NOT here: it has to survive a
 * restart, so it lives on the request record itself (DirectFundingRequestStore
 * beginAttempt/endAttempt), whose life it was already bound to.
 */

import crypto from 'crypto';
import type { IDfLaneKeys } from '../frames';
import type { IDfWitness } from '../messages';
import type { IDfLaneSender } from '../transport/types';

/** One frame this receiver sent, kept so a duplicate offer replays it. */
export interface IDfRecordedResponse {
	subtype: number;
	/** The message body BEFORE sealing (see DfOfferSessions.record). */
	body: Buffer;
}

export interface IDfOfferSession {
	offerIdHex: string;
	/** SHA256 of the decoded offer's exact bytes: what "same content" means. */
	contentHash: string;
	receiptHashHex: string;
	/** `txid:vout`, display byte order. One outpoint, one live session. */
	outpoint: string;
	/** The request this session pays; the frame AAD and the seal's salt. */
	requestId: Buffer;
	/**
	 * Directional keys for the lane the payer last reached us on. Refreshed
	 * when a duplicate offer arrives over a different transport, which is the
	 * only way a payer that lost its answer can be replayed one.
	 */
	keys: IDfLaneKeys;
	laneKey: string;
	/** The response path paired with the current lane keys. */
	reply: IDfLaneSender;
	responses: IDfRecordedResponse[];
	/** Holding a concurrency slot: driving a channel or splice right now. */
	inflight: boolean;
	/** Settled, one way or the other. Nothing restarts. */
	terminal: boolean;
	/**
	 * The payer's witness reached the channel, so our tx_signatures are out and
	 * the funding transaction is the network's. Nothing after this point may be
	 * unwound or declined.
	 */
	committed: boolean;
	/** Set while a session is waiting for the payer's witness frame. */
	onWitness?: (witness: IDfWitness) => void;
	/**
	 * Backstop on the concurrency slot. The session's own deadlines (the
	 * negotiation and the witness wait) always settle it well before this; the
	 * sweep only exists so a slot cannot be pinned by a timer that never fired.
	 */
	slotExpiresAt: number;
	/**
	 * When the RECORD goes. Deliberately later than the slot: forgetting a
	 * session while the payer can still re-send its offer would let a duplicate
	 * begin a second channel session, which is the one thing rev 2 forbids
	 * outright. A terminal session lives as long as its request can be paid.
	 */
	expiresAt: number;
}

export interface IDfOutpointReservation {
	offerIdHex: string;
	expiresAt: number;
}

export class DfOfferSessions {
	private readonly sessions = new Map<string, IDfOfferSession>();
	private readonly reservations = new Map<string, IDfOutpointReservation>();
	/**
	 * Offer ids between the start of admission and its verdict. An admission
	 * awaits a chain lookup, so without this a burst of offers would all pass
	 * the concurrency cap before any of them had taken a slot.
	 */
	private readonly admitting = new Set<string>();

	constructor(private readonly maxSessions: number) {}

	// ─────────────── Sessions ───────────────

	get(offerIdHex: string): IDfOfferSession | undefined {
		return this.sessions.get(offerIdHex);
	}

	/** Live and tombstoned records together, against the map ceiling. */
	size(): number {
		return this.sessions.size;
	}

	atSessionCeiling(): boolean {
		return this.sessions.size >= this.maxSessions;
	}

	/** Sessions holding a concurrency slot, admissions in progress included. */
	inflightCount(): number {
		let live = this.admitting.size;
		for (const s of this.sessions.values()) if (s.inflight) live++;
		return live;
	}

	beginAdmission(offerIdHex: string): boolean {
		if (this.admitting.has(offerIdHex)) return false;
		this.admitting.add(offerIdHex);
		return true;
	}

	endAdmission(offerIdHex: string): void {
		this.admitting.delete(offerIdHex);
	}

	open(session: IDfOfferSession): void {
		this.sessions.set(session.offerIdHex, session);
	}

	/**
	 * A session that only ever produced a decline is forgotten, so a corrected
	 * offer over the same coin and amount is judged fresh rather than answered
	 * from a stale refusal. Anything that reached the funding stage is kept:
	 * that is what makes "never begin a second channel session for a duplicate"
	 * enforceable, and what an id reused with different content is refused
	 * against.
	 */
	forget(offerIdHex: string): void {
		this.sessions.delete(offerIdHex);
	}

	/** Record one outbound message body so a duplicate offer replays it. */
	record(session: IDfOfferSession, subtype: number, body: Buffer): void {
		session.responses.push({ subtype, body: Buffer.from(body) });
	}

	// ─────────────── Outpoint reservations ───────────────

	reservationFor(outpoint: string): IDfOutpointReservation | undefined {
		return this.reservations.get(outpoint);
	}

	reserve(outpoint: string, offerIdHex: string, expiresAt: number): void {
		this.reservations.set(outpoint, { offerIdHex, expiresAt });
	}

	/**
	 * Release on a terminal outcome. The fork released only by TTL (defect
	 * D17), so a coin stayed locked for ten minutes after its session had
	 * settled either way. `holdUntil` keeps the reservation as a cooldown,
	 * which rev 2 asks for after a FAILURE specifically: without it the same
	 * coin can be re-offered at a different amount immediately and burn one
	 * session after another.
	 */
	release(outpoint: string, offerIdHex: string, holdUntil?: number): void {
		const held = this.reservations.get(outpoint);
		if (!held || held.offerIdHex !== offerIdHex) return;
		if (holdUntil === undefined) {
			this.reservations.delete(outpoint);
			return;
		}
		held.expiresAt = holdUntil;
	}

	// ─────────────── Sweep ───────────────

	/** Drop everything expired. Returns how many records went. */
	sweep(now: number): number {
		let dropped = 0;
		for (const [key, session] of this.sessions) {
			// Two clocks, and the slot goes first. A session past its slot
			// backstop has wedged, and the scarce thing it holds is the
			// concurrency slot; the RECORD has to outlive it, or a duplicate
			// offer would find nothing and begin a second channel session.
			if (session.inflight && session.slotExpiresAt <= now) {
				session.inflight = false;
				session.onWitness = undefined;
			}
			if (session.expiresAt > now) continue;
			this.sessions.delete(key);
			dropped++;
		}
		for (const [key, held] of this.reservations) {
			if (held.expiresAt <= now) {
				this.reservations.delete(key);
				dropped++;
			}
		}
		return dropped;
	}

	/** Sessions still waiting for a witness on this lane. */
	witnessWaitersOn(laneKey: string): IDfOfferSession[] {
		const out: IDfOfferSession[] = [];
		for (const s of this.sessions.values()) {
			if (s.laneKey === laneKey && s.onWitness) out.push(s);
		}
		return out;
	}

	clear(): void {
		this.sessions.clear();
		this.reservations.clear();
		this.admitting.clear();
	}
}

/** `txid:vout` in display byte order; the reservation and waiter key. */
export function outpointKey(txidDisplayHex: string, vout: number): string {
	return `${txidDisplayHex}:${vout}`;
}

export function contentHashOf(offerBytes: Buffer): string {
	return crypto.createHash('sha256').update(offerBytes).digest('hex');
}
