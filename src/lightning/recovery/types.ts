/**
 * Recovery Protocol types (docs/RECOVERY-PROTOCOL.md section 5.1 and 5.2).
 *
 * Phase 1 scope: the safety transition layer and the durable outbox. A
 * "safety transition" is the unit of crash consistency: a set of storage
 * mutations plus the outbound wire messages those mutations authorize. Both
 * halves commit in ONE SQLite transaction, and the socket write happens only
 * after that commit returns.
 *
 * Nothing here journals, replicates or encrypts frames; that is Phase 2 and
 * later. The atomicity these types buy is correct on its own and lands
 * unconditionally (spec 5.1, "backward compatibility requirement").
 */

import { IChannelState } from '../channel/channel-state';
import { IChainMonitorState } from '../chain/chain-monitor';
import { IPaymentInfo } from '../node/types';
import {
	IForwardingEvent,
	IInvoiceInfo,
	IRecoveryOutboxMessage,
	IRecoveryOutboxStoredMessage,
	RecoveryOutboxDisposition
} from '../storage/types';

/**
 * How much a transition matters to fund safety, and therefore whether it is
 * journaled (Phase 2) and whether it is subject to a durability barrier
 * (Phase 6). Phase 1 records the classification and uses it only for
 * diagnostics; from Phase 6 a SafetyCritical transition in quorum mode also
 * holds the wire messages it authorizes until its frame is quorum durable.
 */
export enum RecoveryCriticality {
	/** Gossip, mission control: never journaled, always rebuildable. */
	Reconstructable = 'reconstructable',
	/** Journaled, but never allowed to block the protocol. */
	Important = 'important',
	/** Journaled and, from Phase 6, subject to the durability barrier. */
	SafetyCritical = 'safety_critical'
}

/**
 * How durable a safety transition must be before the wire messages it
 * authorizes may reach the peer (docs/RECOVERY-PROTOCOL.md 5.8, Phase 6).
 *
 * - `local`: fsync and continue, replicate opportunistically. Safety equals a
 *   normally persisted node. No fencing guarantee, and nothing promises a
 *   remote copy exists before a peer sees new state.
 * - `async-remote`: fsync, continue, replicate in the background. On
 *   catastrophic device loss the latest replica resumes; a slightly stale
 *   replica means DLP-closing only the channels that advanced past the last
 *   replicated frame. The recommended default for consumer wallets.
 * - `quorum`: fsync, replicate, WAIT for the required receipts, and only then
 *   release the dependent wire message. The guarantee this buys is the point
 *   of the mode: once a peer has seen new channel state from us, sufficient
 *   remote information already exists to restore that state, so a restored
 *   device resumes the channel instead of falling back to DLP.
 *
 * Only `quorum` changes behaviour. `local` and `async-remote` are exactly the
 * node's pre-Phase-6 conduct, which is why the default stays `async-remote`.
 */
export type RecoveryDurability = 'local' | 'async-remote' | 'quorum';

/**
 * One storage mutation inside a transition.
 *
 * Deviation from spec 5.1, which typed the state-bearing variants as opaque
 * `Buffer`: they carry the library's own typed state objects instead. The
 * storage backend already owns the serialization (bigint-safe JSON plus
 * encryption at rest); encoding to Buffer here would duplicate that
 * serializer, and any drift between the two copies would be a
 * silently-corrupt restore. Phase 2 encodes frames at the journal boundary,
 * which is where a canonical byte format actually belongs.
 *
 * The spec's `splice_state` variant is deliberately absent: splice state
 * (`spliceInFlight`, `spliceHistory`) lives inside IChannelState and is
 * already covered by `channel_state`, so a separate variant could only
 * introduce a second, divergent copy.
 */
export type RecoveryMutation =
	| {
			type: 'channel_state';
			channelId: string;
			state: IChannelState;
			peerPubkey: string;
	  }
	| { type: 'channel_key_index'; channelId: string; channelIndex: number }
	| { type: 'chain_monitor'; channelId: string; state: IChainMonitorState }
	| { type: 'payment_preimage'; paymentHash: string; preimage: Buffer }
	| { type: 'htlc_payment_mapping'; htlcKey: string; paymentHash: string }
	| { type: 'delete_htlc_payment_mapping'; htlcKey: string }
	| { type: 'htlc_shared_secret'; key: string; secret: Buffer }
	| { type: 'delete_htlc_shared_secret'; key: string }
	| {
			type: 'forwarded_htlc';
			outKey: string;
			inChannelId: Buffer;
			inHtlcId: bigint;
	  }
	| { type: 'delete_forwarded_htlc'; outKey: string }
	| { type: 'payment_state'; paymentHash: string; payment: IPaymentInfo }
	| { type: 'payment_secret'; paymentHash: string; secret: Buffer }
	| { type: 'delete_payment_secret'; paymentHash: string }
	| { type: 'delete_payment'; paymentHash: string }
	/**
	 * Deleting a preimage is SAFETY-critical in its own right: the
	 * issued-invoice sweep removes expired never-paid BOLT 12 preimages so
	 * the hash stops being claimable, and a restore that resurrected one
	 * would reopen exactly the amplification the sweep closes.
	 */
	| { type: 'delete_preimage'; paymentHash: string }
	| { type: 'invoice_state'; paymentHash: string; invoice: IInvoiceInfo }
	| { type: 'delete_invoice'; paymentHash: string }
	| { type: 'invoice_path_id'; paymentHash: string; pathId: Buffer }
	| { type: 'delete_invoice_path_id'; paymentHash: string }
	| { type: 'forwarding_event'; event: Omit<IForwardingEvent, 'id'> }
	| { type: 'channel_closed'; channelId: string }
	/**
	 * Delete a channel's outbox rows (all of them, or only the given message
	 * types) INSIDE the transition's transaction. This is how a peer-proven
	 * supersede (its revoke_and_ack acknowledged the rows) rides the same
	 * commit as the state that processed the proof: on rollback the rows
	 * survive, so disk can never hold pre-revoke state whose retransmission
	 * bytes are already gone.
	 */
	| { type: 'outbox_supersede'; channelId: string; messageTypes?: number[] };

/**
 * The outbound message and row shapes live in the storage layer that owns the
 * table; these are their spec names (5.2).
 *
 * Storing the EXACT encoded bytes, rather than the material to re-encode
 * them, is load-bearing rather than an optimization: a retransmitted
 * commitment_signed must be byte-identical, because re-signing would bind a
 * fresh MuSig2 secret nonce to material the peer may already hold under the
 * old one (spec 5.10, disposition D2). channel.ts refuses to rebuild a
 * taproot commitment batch for exactly that reason, which today leaves it
 * with nothing to retransmit after a restart; the outbox is what supplies
 * the bytes.
 */
export type RecoveryOutboundMessage = IRecoveryOutboxMessage;
export type IRecoveryOutboxRow = IRecoveryOutboxStoredMessage;
export type { RecoveryOutboxDisposition };

/**
 * The unit of crash consistency: mutations plus the messages they authorize.
 * Only CAUSALLY LINKED mutations belong in one transition (spec 5.1); do not
 * batch unrelated channels together, since that would serialize them behind
 * one lock for no safety gain.
 */
export interface SafetyTransition {
	criticality: RecoveryCriticality;
	mutations: RecoveryMutation[];
	outboundMessages: RecoveryOutboundMessage[];
	/**
	 * Set by a caller that reports commit failures itself (with more context
	 * than this layer has, such as the channel id). The manager then skips its
	 * own error hook, so one failure does not surface as two events.
	 */
	reportedByCaller?: boolean;
}

/** What a caller gets back from a committed transition. */
export interface IRecoveryCommitResult {
	/** True when the SQLite transaction committed. */
	committed: boolean;
	/**
	 * Messages cleared for the wire, in submission order, each with the row id
	 * to mark sent afterwards. EMPTY when the commit failed: a message whose
	 * state did not reach disk must never reach the peer.
	 */
	released: Array<{ id: number | null; message: RecoveryOutboundMessage }>;
	/** Set when the transaction threw; mutations and rows all rolled back. */
	error?: Error;
	/**
	 * The journal frame that carries this transition, or null when the commit
	 * was not journaled (no journal configured, or a Reconstructable
	 * transition). This is the sequence a Phase 6 quorum barrier waits on: the
	 * replication watermark is a CONTIGUOUS quorum-receipted prefix, so
	 * "watermark >= this sequence" proves every frame up to and including this
	 * transition reached the quorum.
	 */
	frameSequence: bigint | null;
}

// ─────────────── Phase 2: the recovery journal (spec 5.3) ───────────────

/**
 * One append-only journal record: everything an Important or SafetyCritical
 * transition changed, hash-chained to its predecessor.
 *
 * Deviation from spec 5.3, same reasoning as RecoveryMutation above: the
 * payload carries the library's typed shapes and the frame codec owns the
 * byte encoding, so there is exactly one serializer (the storage layer's) for
 * every state-bearing object.
 *
 * `snapshot` is present on full-state snapshot frames (spec 5.3, "Snapshots
 * and compaction"): the complete safety-critical state as of this sequence,
 * from which reconstruction starts before replaying later deltas. A snapshot
 * frame's mutations list is empty; the snapshot IS the state.
 */
export interface RecoveryFrame {
	version: 1;
	/** Changes only when a restored device takes ownership (Phase 5). */
	writerEpoch: bigint;
	/** Globally monotonic across the node, starting at 1. */
	sequence: bigint;
	/** Hash of the previous frame's plaintext; 32 zero bytes for frame 1. */
	previousFrameHash: Buffer;
	timestamp: number;
	mutations: RecoveryMutation[];
	outboundMessages: RecoveryOutboundMessage[];
	/**
	 * The durability mode the writer was operating under when it committed
	 * this frame (Phase 6, spec 5.8). Absent on frames written before Phase 6
	 * and on frames from a writer that never configured a mode, which is
	 * indistinguishable from `local` for safety purposes and is treated as
	 * such.
	 *
	 * This is what makes exact restore PROVABLE rather than asserted. A frame
	 * declaring `quorum` is a statement, inside AEAD-authenticated plaintext
	 * bound by the chain hash to the certified head, that every wire message
	 * this frame authorized waited for its receipts. A restore whose certified
	 * head declares `quorum` therefore holds every state a peer could have
	 * seen, which is exactly the condition for resuming instead of falling
	 * back to DLP. See deriveWireSafetyProof in restore-driver.ts.
	 *
	 * A mode DOWNGRADE (quorum to anything weaker) is itself committed under
	 * the barrier it is leaving, so no unbarriered frame can ever hide behind
	 * a certified head that still reads `quorum`.
	 */
	durability?: RecoveryDurability;
	snapshot?: RecoverySnapshot;
}

/**
 * A frame as stored: AEAD ciphertext plus the chain fields kept in the clear
 * so verification and takeover can walk the chain without decrypting.
 */
export interface EncryptedRecoveryFrame {
	writerEpoch: bigint;
	sequence: bigint;
	/** SHA-256 of the plaintext frame bytes. */
	frameHash: Buffer;
	previousFrameHash: Buffer;
	/** AES-256-GCM: iv || authTag || ciphertext. */
	ciphertext: Buffer;
	createdAt: number;
}

/**
 * Every journaled table, serialized whole: the tables RecoveryMutation can
 * touch, plus the outbox. This covers both criticality classes the journal
 * records, SafetyCritical (channels, monitors, preimages, HTLC linkage) and
 * Important (payments, invoices and their path ids, forwarding events), per
 * the spec's classification. Gossip and mission control stay out: they are
 * Reconstructable. Offers remain Phase 3 capsule material; they re-derive
 * from their bech32m encoding and issue no payment-level guarantees.
 *
 * Outbox note: snapshot rows keep their disposition AND the frame_sequence
 * stamp as captured; delta frames record rows at insert time (always
 * pending_send), and disposition advances (markSent) are deliberately NOT
 * journaled. A reconstruction therefore restores post-snapshot rows as
 * pending_send, which errs toward retransmission: the safe direction, since
 * peers treat replays idempotently.
 */
export interface RecoverySnapshot {
	channels: Array<{
		channelId: string;
		state: import('../channel/channel-state').IChannelState;
		peerPubkey: string;
	}>;
	keyIndices: Array<{ channelId: string; channelIndex: number }>;
	chainMonitors: Array<{
		channelId: string;
		state: import('../chain/chain-monitor').IChainMonitorState;
	}>;
	preimages: Array<{ paymentHash: string; preimage: Buffer }>;
	payments: Array<{
		paymentHash: string;
		payment: import('../node/types').IPaymentInfo;
	}>;
	paymentSecrets: Array<{ paymentHash: string; secret: Buffer }>;
	htlcPaymentMappings: Array<{ key: string; paymentHash: string }>;
	forwardedHtlcs: Array<{
		outKey: string;
		inChannelId: Buffer;
		inHtlcId: bigint;
	}>;
	htlcSharedSecrets: Array<{ key: string; secret: Buffer }>;
	invoices: Array<{ paymentHash: string; invoice: IInvoiceInfo }>;
	invoicePathIds: Array<{ paymentHash: string; pathId: Buffer }>;
	forwardingEvents: Array<Omit<IForwardingEvent, 'id'>>;
	outbox: Array<RecoveryOutboundMessage & { frameSequence: number | null }>;
}

/**
 * What RecoveryManager.commit calls to journal a transition, INSIDE the same
 * storage transaction as the transition's writes. A throw here rolls the
 * whole transition back: journaled durability is part of the commit, not a
 * best-effort tail. Kept as an interface so the manager does not import the
 * journal implementation (the journal imports the manager for
 * reconstruction).
 */
export interface IRecoveryJournalSink {
	/**
	 * The sequence the NEXT appended frame will take. The manager stamps the
	 * transition's outbox rows with it BEFORE appending, so a snapshot
	 * captured during the append (bootstrap, or an interval snapshot behind
	 * this delta) already sees the stamped rows.
	 */
	nextSequence(): bigint;
	/** Returns the sequence of the frame that carries this transition. */
	appendFrame(
		mutations: RecoveryMutation[],
		outboundMessages: RecoveryOutboundMessage[]
	): bigint;
}
