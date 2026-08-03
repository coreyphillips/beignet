/**
 * Per-channel recovery status (docs/RECOVERY-PROTOCOL.md 5.6, Phase 5).
 *
 * Richer than a binary exact/stale: after a restore every channel walks
 * through reestablish and lands in exactly one of these, and the two
 * stale-side states carry the protocol's hardest invariant with them: a
 * channel in LocalDataLoss or StateUncertain must NEVER broadcast its
 * stored local commitment, even if the peer stays unreachable forever.
 * Unilateral force close from those states is forbidden; the only safe
 * exits are the peer closing (the DLP path) or an operator explicitly
 * accepting the risk through a clearly-labeled escape hatch that does not
 * exist in this codebase on purpose.
 *
 * String-valued so getRecoveryStatus() reads honestly over the wire and in
 * logs; the variants match the spec's enum member for member.
 */
export enum ChannelRecoveryStatus {
	/** Restored, reestablish not yet exchanged. */
	Quarantined = 'quarantined',
	/** Counters agree, normal resume in progress (e.g. a resumed splice). */
	Reestablishing = 'reestablishing',
	/** Peer needed retransmission; exact bytes served from the outbox. */
	ReplayRequired = 'replay_required',
	/** Peer proved we are stale: existing DLP path, never broadcast. */
	LocalDataLoss = 'local_data_loss',
	/** Cannot prove our state is current: never broadcast, peer closes. */
	StateUncertain = 'state_uncertain',
	Active = 'active',
	ForceClosing = 'force_closing'
}
