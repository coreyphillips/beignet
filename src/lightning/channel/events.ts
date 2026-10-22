import type { ChainMonitor } from '../chain/chain-monitor';
import type { ISweepUneconomicChainAction, OutputType } from '../chain/types';
import type { FforState, IFforEpochRecord } from '../ffor/types';
import type { ILeaseRates } from '../gossip/types';
import type { MessageType } from '../message/types';
import type { Channel } from './channel';
import type { ChannelErrorCode, IChannelPersistEvent } from './channel-actions';
import type { IAbandonedLocalAdd } from './channel-state';

/**
 * Every event ChannelManager emits, with its listener's signature. Arguments
 * are positional, unlike LightningNode, which re-emits most of these as one
 * object. Channel ids are 32-byte Buffers unless the name says hex.
 */
export interface ChannelManagerEvents {
	// ─── Channel lifecycle ───

	/** An outbound open was started; the id is the temporary channel id. */
	'channel:opened': (temporaryChannelId: Buffer) => void;
	/** An inbound open was accepted from this peer. */
	'channel:accepted': (channel: Channel, peerPubkey: string) => void;
	/** A liquidity-ads lease was agreed on an inbound open. */
	'channel:lease': (lease: {
		channelId: Buffer;
		requestedSats: bigint;
		leaseRates: ILeaseRates;
		sellerFundingSatoshis: bigint;
	}) => void;
	/** Funding flow started. */
	'channel:opening': (channelId: Buffer, fundingTxid: Buffer) => void;
	/** Funding reached minimum depth and channel_ready was exchanged. */
	'channel:ready': (channelId: Buffer) => void;
	/** A zero-conf channel is usable before its funding confirms. */
	'channel:zero-conf-ready': (channelId: Buffer) => void;
	/** A channel RESTORED FROM PERSISTENCE in this process completed reestablishment. Fires at most once per channel, never for a channel that stayed live. */
	'channel:restore-ready': (channelId: Buffer) => void;
	/** A channel completed reestablishment back to NORMAL. Fires on EVERY reconnect, so listeners must gate on durable facts. */
	'channel:reestablished': (channelId: Buffer) => void;
	/** The real short channel id was assigned once the funding reached announcement depth. */
	'channel:scid-assigned': (channelId: Buffer, shortChannelId: Buffer) => void;
	/** A caller-driven v2 open owes its tx_signatures. */
	'channel:txsigs-needed': (
		channelId: Buffer,
		fundingTxid: Buffer,
		fundingOutputIndex: number,
		inputIndices: number[],
		externalInputIndices: number[] | undefined
	) => void;
	/** A splice is withholding its tx_signatures on external inputs a third party owes. */
	'channel:splice-txsigs-needed': (
		channelId: Buffer,
		spliceTxid: Buffer,
		newFundingOutputIndex: number,
		externalInputIndices: number[]
	) => void;
	/** A restored v2 open was rolled back or refused. */
	'channel:v2-open-disposed': (
		channelId: Buffer,
		disposition: 'rolled-back' | 'refused'
	) => void;
	/** A negotiated but unfunded open was torn down. */
	'channel:aborted': (temporaryChannelId: Buffer, reason: string) => void;
	/** An unfunded open was removed outright (a v2 open aborted, or dead on disconnect). */
	'channel:abandoned': (channelId: Buffer, reason: string) => void;
	/** The channel failed. */
	'channel:errored': (channelId: Buffer, reason: string) => void;
	/** A cooperative close started. */
	'channel:pending-close': (
		channelId: Buffer,
		initiator: 'local' | 'remote'
	) => void;
	/** A force close started. */
	'channel:force-closing': (
		channelId: Buffer,
		initiator: 'local' | 'remote'
	) => void;
	/** Channel closed. */
	'channel:closed': (channelId: Buffer) => void;
	/** All tracked outputs of the close were irrevocably swept or claimed. */
	'channel:resolved': (channelId: Buffer) => void;
	/** Channel state must be persisted before the batch's messages go out. */
	'channel:persist': (event: IChannelPersistEvent) => void;
	/** A remote revoke_and_ack completed a commitment round. */
	'commitment:revoked': (channelId: Buffer) => void;

	// ─── Funding and chain ───

	/** The funder's BOLT 2 point of no return: broadcast the funding transaction. */
	'funding:authorized': (fundingTxid: Buffer) => void;
	/**
	 * A funding-critical broadcast (a splice, or a v2 funding we contributed
	 * to) cleared its persist and quorum gates and went out. LightningNode
	 * remembers the bytes so a later rebroadcast of the same splice skips
	 * another authorization.
	 */
	'funding:broadcast-authorized': (
		channelId: Buffer | null,
		tx: Buffer
	) => void;
	/** Watch the funding output to this depth. */
	'watch:funding': (
		fundingTxid: Buffer,
		fundingOutputIndex: number,
		minimumDepth: number
	) => void;
	/** Arm spend detection on the outpoints a splice superseded. */
	'watch:presplice-spend': (channelId: Buffer) => void;
	/** Watch this output for a spend. */
	'watch:output': (txid: string, outputIndex: number) => void;
	/** Watch this transaction for confirmation. */
	'watch:tx': (txid: string) => void;
	/** Transaction to broadcast on chain. */
	'broadcast:tx': (tx: Buffer) => void;
	/** A force close's commitment transaction. */
	'force:close': (channelId: Buffer, commitmentTx: Buffer) => void;
	/** A tracked output resolved irrevocably on chain. */
	'output:resolved': (
		txid: string,
		outputIndex: number,
		channelId: Buffer | undefined,
		outputType: OutputType,
		paymentHash: Buffer | undefined,
		htlcId: bigint | undefined
	) => void;
	/** An on-chain claim was declined because it cannot pay its own fee, or a competing spend path opened while it stayed unclaimed. */
	'sweep:uneconomic': (
		channelId: Buffer,
		action: ISweepUneconomicChainAction
	) => void;
	/** The channel's chain monitor changed and must be persisted. */
	'monitor:updated': (channelIdHex: string, monitor: ChainMonitor) => void;
	/** A revoked commitment and its secret, for the watchtower client. A throwing listener leaves the backup owed. */
	'watchtower:backup': (
		channelId: Buffer,
		peerPubkey: string,
		perCommitmentSecret: Buffer,
		revokedTx: Buffer
	) => void;

	// ─── HTLCs ───

	/** A received HTLC is ready to be forwarded or settled. */
	'htlc:forwarded': (
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer
	) => void;
	/** An offered HTLC was fulfilled. */
	'htlc:fulfilled': (
		channelId: Buffer,
		htlcId: bigint,
		preimage: Buffer
	) => void;
	/** An offered HTLC was failed. `malformedCode` is set only for update_fail_malformed_htlc. */
	'htlc:failed': (
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer,
		malformedCode: number | undefined
	) => void;
	/** A confirmed spend of a received HTLC output revealed its preimage; repeats when the spend is re-reported. */
	'htlc:claimed-onchain': (
		channelId: Buffer,
		paymentHash: Buffer,
		preimage: Buffer,
		claimTxid: string
	) => void;
	/** Offered HTLCs the channel dropped on a held restore rather than replay (issue #469). */
	'htlc:local-add-abandoned': (
		channelId: Buffer,
		adds: IAbandonedLocalAdd[]
	) => void;
	/** Preimage recorded. */
	'preimage:learned': (paymentHash: Buffer, preimage: Buffer) => void;

	// ─── Gossip ───

	/** Both announcement signatures are in: the channel can be announced. */
	'announcement:ready': (
		channelId: Buffer,
		channelAnnouncement: Buffer,
		channelUpdate: Buffer
	) => void;
	/** The peer sent announcement_signatures before this node's own were made. */
	'announcement:needs-signing': (
		channelId: Buffer,
		shortChannelId: Buffer
	) => void;

	// ─── Splices and quiescence ───

	/** splice_locked exchanged both ways. */
	'splice:complete': (channelId: Buffer) => void;
	/** A splice negotiation was unwound by tx_abort. */
	'splice:aborted': (channelId: Buffer, reason: string) => void;
	/** The quiescence handshake behind a splice conflict revert request completed with this node as initiator. */
	'splice:conflict-request-ready': (channelId: Buffer) => void;
	/** A conflicted splice was reverted by agreement. */
	'splice:reverted': (
		channelId: Buffer,
		spliceTxid: string,
		conflictTxid: string
	) => void;
	/** The channel left quiescence; parked HTLC dispositions may resume. */
	'quiescence:ended': (channelIdHex: string) => void;
	/** BOLT 2's 60-second quiescence window elapsed with HTLCs pending: the peer must be disconnected. */
	'quiescence:timeout': (channelIdHex: string, peerPubkey: string) => void;

	// ─── Reestablish ───

	/** A peer's channel_reestablish for an unknown channel was parked rather than failed (issue #462). */
	'reestablish:held': (
		peerPubkey: string,
		channelId: Buffer,
		expiresAt: number
	) => void;
	/** This node holds no per-commitment secret for its own channel_reestablish. */
	'reestablish:secret-missing': (
		channelId: Buffer,
		revocationIndex: bigint,
		secretIndex: bigint
	) => void;

	// ─── Transitions (persist-before-send and recovery barriers) ───

	/** A processActions batch opened. */
	'transition:begin': (channelIdHex: string | null) => void;
	/** A processActions batch closed. */
	'transition:end': (channelIdHex: string | null) => void;
	/** A failed persist withheld the batch's messages: reconnect so reestablish replays them. */
	'transition:blocked': (peerPubkey: string, channelId: Buffer | null) => void;
	/** A quorum barrier is holding a batch's messages (informational). */
	'transition:held': (
		peerPubkey: string,
		channelIdHex: string,
		frameSequence: bigint | null
	) => void;
	/** The barrier queue froze: its batches were dropped. */
	'transition:frozen': (
		peerPubkey: string,
		channelIdHex: string,
		reason: string,
		dropped: number
	) => void;
	/** A released batch failed partway through its dispatch. */
	'transition:dispatch-failed': (
		peerPubkey: string,
		channelIdHex: string,
		reason: string,
		dropped: number
	) => void;
	/** A force close detached the channel's parked batches. */
	'transition:terminal-override': (
		peerPubkey: string,
		channelIdHex: string,
		detachedBatches: number
	) => void;
	/** Outbox rows reached the socket. */
	'outbox:sent': (ids: Array<number | null>) => void;

	// ─── FFOR ───

	/** An FFOR epoch's committed state changed. */
	'ffor:state': (
		channelId: Buffer,
		state: FforState,
		record: IFforEpochRecord
	) => void;
	/** Voucher outcomes of an FFOR epoch were committed. */
	'ffor:voucher-outcomes': (
		channelId: Buffer,
		record: IFforEpochRecord
	) => void;
	/** A peer contradicted an ACTIVE FFOR epoch. */
	'ffor:enforce': (channelId: Buffer, record: IFforEpochRecord) => void;

	// ─── Peers and errors ───

	/** Message to send to a peer. */
	'message:outbound': (
		peerPubkey: string,
		type: MessageType,
		payload: Buffer
	) => void;
	/**
	 * A channel-level or protocol error. Node's EventEmitter throws on an
	 * 'error' with no listener, so code that drives a ChannelManager directly
	 * should attach one.
	 */
	error: (
		channelId: Buffer | null,
		message: string,
		code?: ChannelErrorCode
	) => void;
}
