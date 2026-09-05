/**
 * Async payments: type and TLV constants.
 *
 * Async payments let an offline receiver get paid: an always-online LSP holds
 * the inbound HTLC (signalled via the `hold_htlc` marker in the receiver's
 * blinded path) until the receiver comes online and releases it; a `wake`
 * onion message lets the sender nudge the receiver online. The spec is a
 * moving draft, so all wire type numbers live here as named constants in the
 * experimental odd range.
 *
 * Release is authorized by a signed capability (issue #708), never by the
 * payment hash: the hash is disclosed by every invoice, so knowing it proves
 * nothing. See release-capability.ts for the construction.
 */

/**
 * Onion-message TLV carrying a release capability (release-capability.ts)
 * from the receiver to the holding LSP.
 */
export const RELEASE_HELD_HTLC_TLV_TYPE = 1101;

/** Onion-message TLV that nudges an offline receiver to come online. */
export const ASYNC_WAKE_TLV_TYPE = 1103;

/**
 * Onion-message TLV from the holding LSP to the receiver listing the holds
 * parked for it: the hold ids the receiver must sign over to release them.
 */
export const HELD_HTLC_NOTICE_TLV_TYPE = 1105;

/**
 * Onion-message TLV from a receiver asking its LSP for a HELD_HTLC_NOTICE
 * covering everything parked for it.
 */
export const HELD_HTLC_QUERY_TLV_TYPE = 1107;

/**
 * Onion-message TLV from a receiver to a prospective holding LSP asking for
 * an async-receive registration (issue #709). Payload: receiver-grant.ts
 * `encodeRegistrationRequest`.
 */
export const ASYNC_REGISTRATION_REQUEST_TLV_TYPE = 1109;

/**
 * Onion-message TLV from the LSP answering a registration request: a signed
 * receiver grant, or a refusal echoing the request nonce. Payload:
 * receiver-grant.ts `encodeRegistrationReply`.
 */
export const ASYNC_REGISTRATION_REPLY_TLV_TYPE = 1111;

/**
 * LSP-side async receive service configuration (issue #709). The service is
 * DISABLED unless `enabled` is true: a node without it treats a hold_htlc
 * marker as an unknown odd TLV (forwards or fails normally), does not
 * advertise the feature bit, and answers no registration request.
 *
 * Every limit is enforced at admission, atomically with the durable hold
 * row, per receiver and globally. Values a grant carries (the per-receiver
 * ceilings and the fee schedule) are signed into the grant so a receiver
 * knows the terms it registered under.
 */
export interface IAsyncReceiveServiceConfig {
	enabled: boolean;
	/** Registered receivers at once (ACTIVE registrations). Default 1000. */
	maxReceivers?: number;
	/** Largest single held part (msat). Default 1,000,000,000 (0.01 BTC). */
	maxPartMsat?: bigint;
	/** Largest sum of parts held under one payment hash per receiver (msat). Default 1,000,000,000. */
	maxPaymentMsat?: bigint;
	/** Concurrent unresolved holds per receiver. Default 10. */
	maxPartsPerReceiver?: number;
	/** Aggregate unresolved held value per receiver (msat). Default 1,000,000,000. */
	maxHeldMsatPerReceiver?: bigint;
	/** Aggregate bytes reserved by a receiver's unresolved holds. Default 64 KiB. */
	maxHeldBytesPerReceiver?: number;
	/** Concurrent unresolved holds across all receivers. Default 200. */
	maxHolds?: number;
	/** Aggregate unresolved held value across all receivers (msat). Default 10,000,000,000 (0.1 BTC). */
	maxHeldMsat?: bigint;
	/** Aggregate bytes reserved by every unresolved hold. Default 1 MiB. */
	maxHeldBytes?: number;
	/**
	 * Longest a hold may stay parked, in blocks: the CLTV cutoff is clamped
	 * to the admission height plus this. Default 144 (about a day).
	 */
	maxHoldBlocks?: number;
	/**
	 * Fewest blocks a hold must have left before its cutoff to be admitted;
	 * a hold that could not outlive the receiver's next reconnect only burns
	 * a slot. Default 6.
	 */
	minRemainingCltv?: number;
	/** Lifetime of a grant from issuance, in seconds. Default 30 days. */
	grantTtlSec?: number;
	/**
	 * Non-refundable fee per admitted part (msat), debited from the
	 * receiver's prepaid credit at admission whatever the hold's outcome.
	 * Default 0.
	 */
	admissionFeeMsat?: bigint;
	/**
	 * Holding fee per block of reserved hold window (msat), paid by the
	 * SENDER through the LSP hop's payment_relay fee and kept at release,
	 * like any forwarding fee. Default 0.
	 */
	holdingFeeMsatPerBlock?: bigint;
	/**
	 * Prepaid credit (msat) every new registration starts with; the pool the
	 * admission fee is debited from. Default 0, so an admission fee above
	 * zero admits nothing until the operator credits the receiver
	 * (`creditAsyncReceiver`).
	 */
	initialCreditMsat?: bigint;
}

/** Service metrics (issue #709), exposed through getAsyncReceiveServiceMetrics(). */
export interface IAsyncReceiveServiceMetrics {
	enabled: boolean;
	/** ACTIVE, unexpired registrations. */
	registrations: number;
	/** Unresolved holds (HELD, RELEASING, FAILING). */
	occupiedSlots: number;
	/** Sum of the unresolved holds' incoming value (msat, as a string). */
	heldValueMsat: string;
	/** Bytes reserved by the unresolved holds. */
	heldBytes: number;
	/** Creation time (unix ms) of the oldest unresolved hold, or null. */
	oldestHoldAt: number | null;
	/** Admissions refused since this process started, by reason. */
	admissionRefusals: number;
	admissionRefusalsByReason: Record<string, number>;
	/** Holds released (forward placed) since this process started. */
	releases: number;
	/** Holds failed at their CLTV cutoff since this process started. */
	expiries: number;
	/** Holds failed for any other reason since this process started. */
	failures: number;
	/** Registration requests refused since this process started. */
	registrationRefusals: number;
}

/** One parked part as the LSP reports it to the receiver. */
export interface IHeldForwardNoticeEntry {
	/** Random per-hold identity; the thing a capability names. */
	holdId: Buffer;
	paymentHash: Buffer;
	/** What the receiver will be paid for this part once released. */
	forwardAmountMsat: bigint;
	/** Absolute CLTV of the outgoing HTLC the release will place. */
	forwardCltv: number;
	/**
	 * Block height at and after which the LSP no longer releases this part
	 * and fails it upstream instead (the CLTV cutoff, see the ledger).
	 */
	cutoffHeight: number;
	/** The registration the hold was parked under (blinded-path marker). */
	registrationId: Buffer;
}

/** A HELD_HTLC_NOTICE as decoded at the receiver. */
export interface IHeldForwardNotice {
	entries: IHeldForwardNoticeEntry[];
}

const NOTICE_VERSION = 1;
const NOTICE_ENTRY_LEN = 32 + 32 + 8 + 4 + 4 + 32;

/** Encode a HELD_HTLC_NOTICE payload. */
export function encodeHeldForwardNotice(notice: IHeldForwardNotice): Buffer {
	const head = Buffer.alloc(3);
	head.writeUInt8(NOTICE_VERSION, 0);
	head.writeUInt16BE(notice.entries.length, 1);
	const parts: Buffer[] = [head];
	for (const e of notice.entries) {
		if (e.holdId.length !== 32) throw new Error('hold id must be 32 bytes');
		if (e.paymentHash.length !== 32) {
			throw new Error('payment hash must be 32 bytes');
		}
		if (e.registrationId.length !== 32) {
			throw new Error('registration id must be 32 bytes');
		}
		const nums = Buffer.alloc(16);
		nums.writeBigUInt64BE(e.forwardAmountMsat, 0);
		nums.writeUInt32BE(e.forwardCltv, 8);
		nums.writeUInt32BE(e.cutoffHeight, 12);
		parts.push(e.holdId, e.paymentHash, nums, e.registrationId);
	}
	return Buffer.concat(parts);
}

/** Decode a HELD_HTLC_NOTICE payload; null when malformed. */
export function decodeHeldForwardNotice(
	buf: Buffer
): IHeldForwardNotice | null {
	if (buf.length < 3 || buf.readUInt8(0) !== NOTICE_VERSION) return null;
	const count = buf.readUInt16BE(1);
	if (buf.length !== 3 + count * NOTICE_ENTRY_LEN) return null;
	const entries: IHeldForwardNoticeEntry[] = [];
	let off = 3;
	for (let i = 0; i < count; i++) {
		const holdId = Buffer.from(buf.subarray(off, off + 32));
		off += 32;
		const paymentHash = Buffer.from(buf.subarray(off, off + 32));
		off += 32;
		const forwardAmountMsat = buf.readBigUInt64BE(off);
		off += 8;
		const forwardCltv = buf.readUInt32BE(off);
		off += 4;
		const cutoffHeight = buf.readUInt32BE(off);
		off += 4;
		const registrationId = Buffer.from(buf.subarray(off, off + 32));
		off += 32;
		entries.push({
			holdId,
			paymentHash,
			forwardAmountMsat,
			forwardCltv,
			cutoffHeight,
			registrationId
		});
	}
	return { entries };
}
