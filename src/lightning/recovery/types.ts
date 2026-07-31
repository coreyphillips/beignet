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
	IRecoveryOutboxMessage,
	IRecoveryOutboxStoredMessage,
	RecoveryOutboxDisposition
} from '../storage/types';

/**
 * How much a transition matters to fund safety, and therefore whether it is
 * journaled (Phase 2) and whether it is subject to a durability barrier
 * (Phase 6). Phase 1 records the classification and uses it only for
 * diagnostics; no barrier exists yet.
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
	| { type: 'channel_closed'; channelId: string };

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
}
