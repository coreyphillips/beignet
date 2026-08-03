/**
 * The wire-safety proof: the object that lets a restored device RESUME a
 * channel instead of falling back to DLP (docs/RECOVERY-PROTOCOL.md 5.6, 5.8,
 * Phase 6).
 *
 * Phase 5 deliberately left no way to skip StateUncertain. Every restored
 * channel was marked, permanently, because guardian replication was best
 * effort and a compatible `channel_reestablish` proves nothing about
 * exactness: a peer can under-report its counters while holding a newer
 * state. An earlier attempt at an escape hatch, a caller-supplied
 * `wireSafeThroughSequence` scalar, was removed for a reason worth restating:
 * a bare number is bound to nothing, so one mistaken config value could
 * launder a stale restore into a broadcastable one.
 *
 * This is that escape hatch done properly. It is not configuration, it is
 * evidence, and it is derived from the restore itself rather than supplied to
 * it. The argument it encodes:
 *
 *   In quorum mode no IRREVERSIBLE wire message leaves before the journal
 *   frame that authorized it has reached a guardian quorum. Irreversible
 *   means the gated set: revoke_and_ack, commitment_signed,
 *   update_fulfill_htlc, tx_signatures, splice_locked, and the recovery
 *   declarations that establish the never-broadcast invariant.
 *
 *   The premise is narrower than "no wire message" on purpose, and the gap is
 *   what carries the argument rather than weakening it. Everything ungated is
 *   an UNCOMMITTED update (update_add_htlc, update_fail_htlc, update_fee), a
 *   negotiation step that simply restarts (shutdown, closing_signed, the
 *   interactive-tx and splice preamble) or a message the reestablish rules
 *   regenerate (channel_ready, channel_reestablish). BOLT 2 requires the peer
 *   to discard every one of them across a reconnect that did not commit them,
 *   so none can leave the peer holding a commitment we do not, or a
 *   revocation for a commitment the restored chain still believes is current.
 *
 *   So for every message that irrevocably advanced or discarded commitment
 *   state, the frame behind it is at or below the certified head. A restore
 *   installed AT that head therefore holds every such state the peer could
 *   possibly know about, and in particular can hold no commitment the peer
 *   has already seen us revoke. That is exactly the condition for resuming.
 *
 * The premise is checked, not assumed. The head frame's own plaintext has to
 * declare `quorum`, and that declaration lives inside AEAD-authenticated
 * bytes whose hash the guardians certified, so it cannot be edited after the
 * fact by anyone who did not hold the writer key. The sticky rule in the
 * journal supplies the other half: a chain containing a quorum frame can
 * never be followed by an unbarriered one, so a certified head reading
 * `quorum` also rules out unbarriered frames ABOVE it, which are the frames a
 * restore cannot see.
 */

import { WIRE_SAFETY_POLICY_VERSION } from '../channel/channel-actions';
import { GuardianState } from './guardian-wire';
import { RecoveryFrame, VerifiedRecoveryChain } from './types';

/**
 * Evidence that a restore at this head is exact. Every field is part of the
 * binding, not decoration: the namespace it is about, the epoch it took over
 * from, the head it was derived at (sequence AND frame hash, because a
 * sequence alone names a position rather than a chain), and the mode the head
 * declared.
 */
export interface IWireSafetyProof {
	recoveryId: Buffer;
	/** The epoch this restore superseded, from the certified state. */
	supersededEpoch: bigint;
	headSequence: bigint;
	headFrameHash: Buffer;
	/** Always `quorum`; anything else is not a proof and is never built. */
	durability: 'quorum';
	/**
	 * The barrier policy the WRITER enforced, copied from the head frame's own
	 * authenticated plaintext. Not the restorer's own constant: that would be
	 * a self-report, and this field exists precisely so a build cannot read an
	 * older writer's `quorum` as a promise about a set it never held.
	 */
	policyVersion: number;
}

/** Why a restore could not be shown to be exact. */
export type WireSafetyRefusal =
	| 'no-frames'
	| 'head-mismatch'
	| 'not-quorum'
	| 'policy-mismatch'
	| 'namespace-mismatch';

export type WireSafetyDerivation =
	| { proven: true; proof: IWireSafetyProof }
	| { proven: false; reason: WireSafetyRefusal; detail: string };

/**
 * Derive the proof from a verified restore, or explain why there is none.
 *
 * Call this only with frames that verifyFrameChain has already accepted
 * against `certified`: this function asks whether an authenticated chain
 * justifies resuming, not whether the chain is authentic.
 */
export function deriveWireSafetyProof(
	certified: GuardianState,
	frames: VerifiedRecoveryChain,
	recoveryId: Buffer
): WireSafetyDerivation {
	if (!certified.recoveryId.equals(recoveryId)) {
		return {
			proven: false,
			reason: 'namespace-mismatch',
			detail: 'the certified state belongs to a different recovery namespace'
		};
	}
	const head = frames[frames.length - 1];
	if (!head) {
		return {
			proven: false,
			reason: 'no-frames',
			detail: 'nothing was restored, so nothing is proven about it'
		};
	}
	// The head we reason about must BE the head the guardians certified. A
	// proof derived from a frame the quorum never acknowledged would be a
	// statement about a chain nobody else holds.
	if (head.sequence !== certified.logHead.sequence) {
		return {
			proven: false,
			reason: 'head-mismatch',
			detail: `the restored chain ends at ${head.sequence}, not at the certified head ${certified.logHead.sequence}`
		};
	}
	if (head.durability !== 'quorum') {
		return {
			proven: false,
			reason: 'not-quorum',
			detail:
				`the certified head declares durability ` +
				`'${head.durability ?? 'none'}', so a message it authorized may have ` +
				'reached a peer before this state reached the guardians'
		};
	}
	// The head declares quorum, but quorum under WHOSE policy? The stamp names
	// the message set the writer actually held back. A version this build does
	// not know is not corruption, it is a chain this build cannot reason
	// about, so it refuses and the DLP fallback stays in place.
	//
	// Exact match rather than a range: a lower version guarantees a weaker set
	// than the argument above assumes, and a higher one is a set this build has
	// never seen. A future release that establishes "v2 implies v1" can add an
	// explicit table; accepting silently is the laundering this field exists
	// to prevent.
	if (head.durabilityPolicy !== WIRE_SAFETY_POLICY_VERSION) {
		return {
			proven: false,
			reason: 'policy-mismatch',
			detail:
				`the certified head was written under wire-safety policy ` +
				`'${String(head.durabilityPolicy ?? 'none')}', and this build can ` +
				`only reason about policy ${WIRE_SAFETY_POLICY_VERSION}`
		};
	}
	return {
		proven: true,
		proof: {
			recoveryId: Buffer.from(recoveryId),
			supersededEpoch: certified.lease.epoch,
			headSequence: certified.logHead.sequence,
			headFrameHash: Buffer.from(certified.logHead.frameHash),
			durability: 'quorum',
			policyVersion: head.durabilityPolicy
		}
	};
}

/**
 * Re-check a proof against the restore it claims to describe.
 *
 * The driver derives its own proof and then verifies it here before acting on
 * it. That looks redundant and is not: it makes the acceptance condition a
 * single readable predicate that a test can exercise directly, and it means
 * any future caller that obtains a proof from somewhere else is held to the
 * same standard rather than trusted.
 */
export function verifyWireSafetyProof(
	proof: IWireSafetyProof,
	against: { certified: GuardianState; recoveryId: Buffer; head: RecoveryFrame }
): boolean {
	return (
		proof.durability === 'quorum' &&
		proof.policyVersion === WIRE_SAFETY_POLICY_VERSION &&
		// The load-bearing one: it binds the proof's version to the FRAME's
		// own stamp, so the field is evidence about the writer rather than a
		// self-report by whoever built the proof.
		against.head.durabilityPolicy === proof.policyVersion &&
		proof.recoveryId.equals(against.recoveryId) &&
		against.certified.recoveryId.equals(against.recoveryId) &&
		proof.supersededEpoch === against.certified.lease.epoch &&
		proof.headSequence === against.certified.logHead.sequence &&
		proof.headFrameHash.equals(against.certified.logHead.frameHash) &&
		against.head.sequence === proof.headSequence &&
		against.head.durability === 'quorum'
	);
}
