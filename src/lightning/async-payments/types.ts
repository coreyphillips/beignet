/**
 * Async payments (draft) — type & TLV constants.
 *
 * Async payments let an offline receiver get paid: an always-online LSP holds
 * the inbound HTLC (signalled via the `hold_htlc` marker in the receiver's
 * blinded path) until the receiver comes online and sends a `release_held_htlc`
 * onion message; a `wake` onion message lets the sender nudge the receiver
 * online. The spec is a moving draft, so all wire type numbers live here as
 * named constants in the experimental odd range.
 */

/** Onion-message TLV carrying a 32-byte payment hash to release a held HTLC. */
export const RELEASE_HELD_HTLC_TLV_TYPE = 1101;

/** Onion-message TLV that nudges an offline receiver to come online. */
export const ASYNC_WAKE_TLV_TYPE = 1103;

/** A forward parked by the LSP on behalf of an offline receiver. */
export interface IHeldForward {
	/** Payment hash the release message references. */
	paymentHash: Buffer;
	/** Perform the deferred onward forward to the (now-online) receiver. */
	release: () => void;
	/** Fail the parked inbound HTLC back to the sender. */
	fail: () => void;
}
