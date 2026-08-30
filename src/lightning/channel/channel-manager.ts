/**
 * BOLT 2: Channel Manager.
 *
 * Glue layer that maps PeerManager messages to Channel instances,
 * handling multiplexing and dispatch. Bridges the transport-agnostic
 * Channel state machine to the actual transport layer.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import { MessageType } from '../message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../message/channel-funding';
import {
	decodeUpdateAddHtlcMessage,
	decodeUpdateFulfillHtlcMessage,
	decodeUpdateFailHtlcMessage,
	decodeUpdateFailMalformedHtlcMessage,
	decodeUpdateFeeMessage,
	decodeUpdateBlockheightMessage
} from '../message/channel-update';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../message/channel-commitment';
import {
	decodeShutdownMessage,
	encodeShutdownMessage,
	decodeClosingSignedMessage,
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	ClosingSigVariant,
	IClosingCompleteMessage
} from '../message/channel-close';
import {
	canScopeWireError,
	decodeErrorMessage,
	encodeErrorMessage
} from '../message/error';
import { decodeChannelReestablishMessage } from '../message/channel-reestablish';
import { decodeStfuMessage } from '../message/stfu';
import {
	decodeSpliceMessage,
	decodeSpliceAckMessage,
	decodeSpliceLockedMessage,
	decodeStartBatchMessage
} from '../message/splice';
import {
	ChannelAction,
	ChannelActionType,
	IBroadcastTxAction,
	IChannelPersistEvent,
	IChannelPersistRequest,
	IErrorAction,
	ISendMessageAction,
	IWireDurabilityBarrier,
	QUORUM_BARRIER_MESSAGE_TYPES,
	RETRANSMITTABLE_MESSAGE_TYPES,
	SUPERSEDED_ON_REVOKE_MESSAGE_TYPES
} from './channel-actions';
import * as bitcoin from 'bitcoinjs-lib';
import { ChainMonitor } from '../chain/chain-monitor';
import {
	ChainAction,
	ChainActionType,
	CommitmentType,
	IFeeBumpAndBroadcastChainAction,
	IFundingSpendScan,
	IRREVOCABLE_DEPTH,
	satPerVbyteToSatPerKw
} from '../chain/types';
import {
	attachFeeInputsToZeroFeeHtlcTx,
	buildAnchorCpfpTx
} from '../chain/sweep';
import {
	ANCHOR_OUTPUT_VALUE,
	buildAnchorOutput,
	buildAnchorScript
} from '../script/anchor';
import type { IFundingProvider } from '../node/types';
import {
	canSelectDualFundingInputs,
	releaseInputPledgesBestEffort,
	selectDualFundingContribution,
	verifyDirectedSelection
} from '../node/funding-selection';
import type { IDualFundingSelection } from '../node/funding-selection';
import { ChannelSigner, ISigner, SignerFactory } from '../keys/signer';
import {
	signRemoteCommitment,
	signRemoteCommitmentPartial,
	signRemoteHtlcSignaturesTaproot
} from './commitment-builder';
import { generateNonce, type SessionKey } from '../crypto/musig';
import {
	taprootCommitmentSighash,
	startCommitmentSigningSession,
	verifyPartialCommitmentSig,
	aggregateCommitmentSig
} from './commitment-musig';
import {
	createTaprootFundingScript,
	buildTaprootKeySpendWitness
} from '../script/funding-taproot';
import { buildTaprootAnchorOutput } from '../script/commitment-taproot';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Channel, ISpliceWalletInput, ITaprootClosingCache } from './channel';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from './channel-state';
import {
	deriveChannelId,
	deriveV2TemporaryChannelId,
	isValidShutdownScript
} from './validation';
import {
	IChannelConfig,
	DEFAULT_CHANNEL_CONFIG,
	ChannelResult,
	ChannelState,
	ChannelRole,
	HtlcDirection,
	HtlcState,
	hasScidAliasChannelType,
	isAnchorChannel,
	isTaprootChannel,
	scidAliasAnnounceRefusal,
	validateV2ChannelType,
	MAX_FUNDING_SATOSHIS,
	MAX_WUMBO_FUNDING_SATOSHIS
} from './types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret,
	derivePublicKey,
	derivePrivateKey
} from '../keys/derivation';
import { getPublicKey } from '../crypto/ecdh';
import { generateFromSeed } from '../keys/shachain';
import { PeerManager } from '../transport/peer-manager';
import { ZeroConfManager } from './zero-conf';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxRemoveInputMessage,
	decodeTxRemoveOutputMessage,
	decodeTxCompleteMessage,
	decodeTxSignaturesMessage,
	decodeTxInitRbfMessage,
	decodeTxAckRbfMessage,
	decodeTxAbortMessage,
	ITxAddInputMessage
} from '../message/interactive-tx';
import {
	DualFundingSession,
	DualFundingState,
	IDualFundingParams
} from './dual-funding';
import { ILeaseRates } from '../gossip/types';
import {
	LEASE_DURATION_BLOCKS,
	signWillFund,
	verifyWillFund
} from './liquidity-ads';
import { decodeAnnouncementSignaturesMessage } from '../gossip/messages';
import { Feature, FeatureFlags } from '../features/flags';

/**
 * The outpoints a raw transaction spends, txid in display-order hex (the
 * form the funding provider keys its pledges by). Unreadable hex cannot
 * name a pledge, so it maps to no outpoints; the pledge TTL covers it.
 */
export function txInputOutpoints(
	txHex: string
): Array<{ txid: string; vout: number }> {
	try {
		return bitcoin.Transaction.fromHex(txHex).ins.map((input) => ({
			txid: Buffer.from(input.hash).reverse().toString('hex'),
			vout: input.index
		}));
	} catch {
		return [];
	}
}

/** Per-channel key set returned by the channel key deriver callback. */
export interface IPerChannelKeys {
	fundingPrivkey: Buffer;
	basepoints: IChannelBasepoints;
	perCommitmentSeed: Buffer;
	htlcBasepointSecret?: Buffer;
	revocationBasepointSecret?: Buffer;
	paymentBasepointSecret?: Buffer;
	delayedPaymentBasepointSecret?: Buffer;
}

/** A batch suffix parked behind the quorum barrier (Recovery 5.8). */
interface IHeldBatch {
	actions: ChannelAction[];
	/** Index in `actions` the held run resumes from. */
	from: number;
	/** The journal frame the batch's persist landed in. */
	frameSequence: bigint | null;
	/**
	 * The held suffix carries a message the barrier gates, so it may not be
	 * dispatched until `frameSequence` is quorum durable.
	 *
	 * False for a batch queued purely to preserve wire ORDER behind one that
	 * does. Those carry no frame of their own, and putting them to the barrier
	 * anyway would refuse a shutdown, a closing_signed round or an stfu for
	 * doing nothing that needs durability. They wait for their turn, not for a
	 * receipt.
	 */
	requiresDurability: boolean;
	/** Outbox rows to mark sent once the bytes actually leave. */
	outboxIds: Array<number | null>;
}

/** Observable progress through one synchronous action dispatch. */
interface IActionDispatchProgress {
	/** Action currently being attempted, or -1 before dispatch starts. */
	index: number;
	/** Last action that returned normally, or -1 when none completed. */
	completedIndex: number;
	/** Wire message types whose transport call was attempted. */
	attemptedMessageTypes: Set<number>;
	/** A failed persist withheld one or more wire effects. */
	sendsWithheld: boolean;
	/**
	 * One or more sends were parked behind the quorum durability barrier, or
	 * dropped for want of frame attribution, instead of reaching the transport.
	 * Kept apart from `sendsWithheld` because the two have opposite dispositions
	 * here: a withheld batch committed nothing, while a held one committed its
	 * state and is waiting for a receipt that may still be refused.
	 */
	sendsHeld: boolean;
}

function newDispatchProgress(): IActionDispatchProgress {
	return {
		index: -1,
		completedIndex: -1,
		attemptedMessageTypes: new Set<number>(),
		sendsWithheld: false,
		sendsHeld: false
	};
}

/** Why a new channel is refused once the recovery namespace is finished. */
const NAMESPACE_LOST_REFUSAL =
	'recovery: this namespace lost its guardian backfill, so a new channel ' +
	'could never be proven durable; close the existing channels and provision ' +
	'a new namespace';

/** One channel's held batches, released strictly in order. */
interface IBarrierQueue {
	peerPubkey: string;
	channel: Channel;
	batches: IHeldBatch[];
}

export interface IChannelManagerConfig {
	localConfig?: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
	localFundingPrivkey: Buffer;
	/** HTLC basepoint secret for signing HTLC second-level transactions */
	htlcBasepointSecret?: Buffer;
	/** Revocation basepoint secret for penalty sweeps */
	revocationBasepointSecret?: Buffer;
	/** Payment basepoint secret for to_remote claims */
	paymentBasepointSecret?: Buffer;
	/** Delayed payment basepoint secret for to_local claims */
	delayedPaymentBasepointSecret?: Buffer;
	/** Prefer anchor channels (option_anchors_zero_fee_htlc_tx) */
	preferAnchors?: boolean;
	/**
	 * Propose simple taproot channels (option_taproot). MuSig2 funding and
	 * commitment signing (deterministic verification nonces) are fully wired;
	 * the complete lifecycle is validated against LND on regtest. Off by
	 * default because the feature bit is still in staging upstream (180/181).
	 */
	preferTaproot?: boolean;
	/**
	 * Quorum durability barrier (docs/RECOVERY-PROTOCOL.md 5.8, Phase 6).
	 * Absent, or present but not enforcing, leaves dispatch entirely
	 * synchronous. When enforcing, a batch carrying a barrier-class message
	 * holds the rest of its actions until the journal frame behind it has
	 * reached a quorum of guardians.
	 */
	durabilityBarrier?: IWireDurabilityBarrier;
	/** Chain hash for open_channel messages (defaults to Bitcoin mainnet) */
	chainHash?: Buffer;
	/** Node identity private key (for announcements) */
	nodePrivateKey?: Buffer;
	/**
	 * Per-channel key derivation callback. If provided, each new channel gets
	 * unique keys. MUST be pure and deterministic: an index has to answer
	 * with the same material every time, since basepoints are committed to on
	 * chain while signing secrets are re-derived at restart and recovery.
	 */
	channelKeyDeriver?: (channelIndex: number) => IPerChannelKeys;
	/**
	 * Custom {@link ISigner} factory (e.g. a remote/external signer). When
	 * set, it replaces the internal ChannelSigner construction for every
	 * channel signer, keyed by the channel's key index (0 for node-level
	 * shared keys). The raw key Buffers in this config remain required for
	 * non-signer paths (sweeps, monitors); library-level injection only.
	 */
	signerFactory?: SignerFactory;
	/**
	 * Liquidity ads (bLIP-0051): when set, this node sells inbound liquidity at
	 * these rates — it answers a buyer's request_funds with a signed will_fund
	 * and contributes the requested funds as the acceptor.
	 */
	leaseRates?: ILeaseRates;
	/**
	 * Our own advertised init features. Used to gate per-peer feature-dependent
	 * behavior (e.g. option_simple_close) on BOTH sides having advertised it.
	 * When absent, feature-gated behavior stays on the legacy path.
	 */
	localFeatures?: FeatureFlags;
	/**
	 * option_wumbo (large_channels, bit 18): lift the 2^24 sat funding cap to
	 * MAX_WUMBO_FUNDING_SATOSHIS for peers that ALSO advertised the bit. Off by
	 * default: every open/accept/v2/splice keeps the BOLT 2 cap.
	 */
	largeChannels?: boolean;
	/**
	 * Live on-chain feerate (sat/kw) for cooperative closing transactions.
	 * Called at each closing entry point. Anchor channels pin the commitment
	 * feerate to the 253 sat/kw floor, so without this the closing fee is
	 * derived from that floor and spec peers reject the negotiation as below
	 * their minimum acceptable fee. When absent (or returning undefined) the
	 * channel falls back to its commitment feerate.
	 */
	getClosingFeeratePerKw?: () => number | undefined;
	/**
	 * Optional chain-backed, best-effort verification of a v2 peer's
	 * tx_add_input prevout (issue #311). Every local prev_tx check is
	 * self-consistency over bytes the peer chose. Called fire-and-forget as
	 * peer inputs arrive; only 'spent-or-missing' (positive evidence the
	 * prevout was spent) aborts the negotiation, anything else proceeds
	 * (fail open; absence from a server's view is never conclusive, since
	 * BOLT 2 permits unconfirmed inputs). `txid` is internal byte order.
	 * Absent means no verification.
	 */
	verifyRemoteFundingInput?: (input: {
		txid: Buffer;
		vout: number;
		scriptPubKey: Buffer;
	}) => Promise<'unspent' | 'spent-or-missing' | 'unknown'>;
	/**
	 * Whether a durable channel row a restart could restore survives for
	 * this id (issue #311). Consulted before releasing the funding pledges
	 * of an abandoned v2 open: the node's channel:abandoned listener can
	 * leave a row untouched when the store cannot answer, and a restart
	 * would then resume an open whose inputs are no longer reserved.
	 * Implementations must answer true when unsure (a read failure keeps
	 * the pledge; the TTL is the backstop). Absent means no durable rows
	 * exist (no storage).
	 */
	hasResumableChannelRow?: (channelId: Buffer) => boolean;
	/**
	 * BOLT 2 quiescence watchdog window in ms (default 60_000): "MUST
	 * disconnect after 60 seconds of quiescence if the HTLCs are pending".
	 * Injectable so tests can shrink it.
	 */
	quiescenceTimeoutMs?: number;
	/**
	 * How long an inbound channel_reestablish naming a channel this node has
	 * NO record of is held before it is answered with the BOLT 1 error
	 * (docs/RECOVERY-PROTOCOL.md 5.7, issue #462). Absent or 0 keeps the
	 * historical conduct: the error goes out immediately.
	 *
	 * Set only by a node that may be an INCOMPLETE restore target, which
	 * today means peer-storage recovery mode: its database is deliberately
	 * empty until the operator applies a Recovery Capsule, and the capsule
	 * arrives in the same instant as the peer's reestablish, so erroring
	 * makes the peer force-close a channel the restore is about to resume.
	 * A peer waits indefinitely for an unanswered reestablish, but reads an
	 * error as a permanent failure, so holding is the recoverable direction.
	 *
	 * The hold covers the unknown-channel case ONLY. FORCE_CLOSED, CLOSED
	 * and ERRORED are channels this node does know about, and their answer
	 * is never deferred. The error is deferred, never dropped: one window
	 * per (peer, channel) per process, after which the peer gets exactly the
	 * reply it gets today.
	 */
	unknownChannelReestablishHoldMs?: number;
}

/**
 * Manages multiple channels, dispatching messages between PeerManager
 * and Channel instances.
 *
 * Events:
 * - 'channel:opened' (channelId: Buffer)
 * - 'channel:opening' (channelId: Buffer, fundingTxid: Buffer)
 * - 'channel:ready' (channelId: Buffer)
 * - 'channel:restore-ready' (channelId: Buffer) — a channel RESTORED FROM
 *   PERSISTENCE this process has completed reestablishment; fires at most
 *   once per channel and never for a channel that stayed live
 * - 'channel:reestablished' (channelId: Buffer) — a channel completed
 *   reestablishment back to NORMAL; fires on EVERY reconnect, so listeners
 *   must gate on durable facts, never on in-memory state having been lost
 * - 'channel:scid-assigned' (channelId: Buffer, shortChannelId: Buffer)
 * - 'channel:pending-close' (channelId: Buffer, initiator: 'local' | 'remote')
 * - 'channel:force-closing' (channelId: Buffer, initiator: 'local' | 'remote')
 * - 'channel:closed' (channelId: Buffer)
 * - 'htlc:forwarded' (channelId: Buffer, htlcId: bigint, amountMsat: bigint, paymentHash: Buffer)
 * - 'htlc:fulfilled' (channelId: Buffer, htlcId: bigint, preimage: Buffer)
 * - 'htlc:failed' (channelId: Buffer, htlcId: bigint, reason: Buffer)
 * - 'quiescence:ended' (channelIdHex: string) — the channel left quiescence;
 *   parked HTLC dispositions may resume
 * - 'quiescence:timeout' (channelIdHex: string, peerPubkey: string) — BOLT 2's
 *   60-second quiescence window elapsed with HTLCs pending; the peer must be
 *   disconnected
 * - 'reestablish:held' (peerPubkey: string, channelId: Buffer, expiresAt: number):
 *   a peer's channel_reestablish for a channel we have no record of was parked
 *   rather than failed, because this node may still be an incomplete restore
 *   target (issue #462); the operator has until expiresAt to install the state
 *   that answers it
 * - 'error' (channelId: Buffer | null, message: string)
 */

/**
 * Blocks to wait between re-CPFP attempts on a stuck anchor force-close commitment
 * package (matches the ChainMonitor sweep rebroadcast cadence).
 */
const COMMITMENT_CPFP_REBUMP_INTERVAL = 6;

/** BOLT 2: "MUST disconnect after 60 seconds of quiescence if the HTLCs are pending". */
const DEFAULT_QUIESCENCE_TIMEOUT_MS = 60_000;

/**
 * Ceiling on held unknown-channel reestablishes PER PEER (issue #462). A peer
 * streaming fabricated channel ids would otherwise buy a timer and a payload
 * buffer per id. Per peer rather than global so that spending it is always
 * self-inflicted: a peer that exhausts its own quota gets the immediate error
 * for its next id, and every other peer keeps a full quota of its own. Far
 * above any real topology (nodes rarely hold more than a handful of channels
 * with one peer), so a genuine restore never reaches it.
 *
 * Spent windows stay in the map and count toward this, so the ceiling bounds
 * windows granted per peer per process, not just windows open at once.
 */
const MAX_HELD_UNKNOWN_REESTABLISH_PER_PEER = 64;

/**
 * Ceiling across all peers, a memory backstop rather than a policy: the
 * per-peer quota is what protects honest peers, and this only bounds what a
 * flood of distinct peer identities can cost. Reaching it declines the hold,
 * which is the safe direction (it is what an unconfigured node does).
 */
const MAX_HELD_UNKNOWN_REESTABLISH = 1024;

/**
 * setTimeout turns anything past 2^31-1 ms into a 1 ms delay, which would
 * make an over-large hold window fire instantly and look like no hold at all.
 * Out-of-range windows decline the hold outright instead (issue #462).
 */
const MAX_UNKNOWN_REESTABLISH_HOLD_MS = 2_147_483_647;

/** BOLT 1 length-prefixes the error `data` field with a u16. */
const MAX_WIRE_ERROR_DATA_BYTES = 0xffff;

/**
 * `reason` as wire bytes, clamped to what the length prefix can carry.
 *
 * Not every reason is ours: abortPendingOpen quotes an IFundingProvider error
 * verbatim, so an embedder that throws more than 64 KiB of text would otherwise
 * take encodeErrorMessage down with it. Clamped rather than refused because the
 * peer is mid-negotiation: a truncated cancellation still frees it, while no
 * message at all leaves it parked on an open that will never answer.
 *
 * The cut backs off over any UTF-8 continuation bytes it orphaned, so the
 * operator at the far end never reads a split character.
 *
 * @param reason - Human-readable text for the peer's operator
 * @returns The data field, at most MAX_WIRE_ERROR_DATA_BYTES long
 */
function clampWireErrorData(reason: string): Buffer {
	const data = Buffer.from(reason, 'utf8');
	if (data.length <= MAX_WIRE_ERROR_DATA_BYTES) return data;
	let end = MAX_WIRE_ERROR_DATA_BYTES;
	while (end > 0 && (data[end] & 0xc0) === 0x80) end--;
	return data.subarray(0, end);
}

/**
 * The payload for a BOLT 1 error scoped to `channelId`, or null when this id
 * cannot carry one (canScopeWireError says which, and why).
 *
 * The manager-layer twin of Channel.wireErrorFor, returning a payload rather
 * than an action because some of the sites here hand it straight to
 * sendMessage while others wrap it in a SEND_MESSAGE action. Every wire error
 * this class produces routes through it, for the reason refuseInboundOpen used
 * to give for its own inline copy: a caller-side check protects only the caller
 * that remembers to make it, and several of these sites take an id straight off
 * the wire whose safety currently rests on a guard in a DIFFERENT handler
 * (funding_created quotes the temporary id open_channel screened). A null here
 * suppresses the wire half only; the local refusal, the cleanup and the event
 * still stand.
 *
 * @param channelId - The id the error would be scoped to
 * @param reason - Human-readable text for the peer's operator
 * @returns The encoded error payload, or null when the id cannot carry one
 */
function wireErrorPayloadFor(channelId: Buffer, reason: string): Buffer | null {
	if (!canScopeWireError(channelId)) return null;
	return encodeErrorMessage({
		channelId,
		data: clampWireErrorData(reason)
	});
}

export class ChannelManager extends EventEmitter {
	private config: IChannelManagerConfig;
	private channels: Map<string, Channel> = new Map();
	private tempChannels: Map<string, Channel> = new Map();
	private channelPeers: Map<string, string> = new Map();
	/** Synchronous funding promotions reserved across reentrant observers. */
	private channelIdReservations: Map<string, Channel> = new Map();
	/**
	 * Channels restored from persistence in THIS process whose node-level
	 * repair pass has not run yet (see 'channel:restore-ready'). Emptied one
	 * channel at a time as each completes reestablishment, so the repair can
	 * never run for a channel that has been live all along.
	 */
	private channelsAwaitingRestoreRepair: Set<string> = new Set();
	/**
	 * BOLT 2 quiescence watchdog: one timer per quiescing channel. Timer
	 * presence doubles as the "was quiescing" latch, so clearing one emits
	 * 'quiescence:ended'. Timers are unref'd and cleared on detach.
	 */
	private quiescenceTimers: Map<string, ReturnType<typeof setTimeout>> =
		new Map();
	/**
	 * Inbound channel_reestablish messages parked because they name a channel
	 * this node has no record of and the node is an incomplete restore target
	 * (issue #462; see unknownChannelReestablishHoldMs). Keyed
	 * `${peerPubkey}:${channelIdHex}`.
	 *
	 * `deadline` is absolute and outlives its timer, so a disconnect can drop
	 * the timer while the entry keeps the clock: a peer that reconnects gets
	 * the REMAINDER of its original window, never a fresh one. An entry whose
	 * deadline has passed stays in the map as a tombstone, which is what makes
	 * the window one-per-(peer, channel) for the life of the process.
	 */
	private heldUnknownReestablish: Map<
		string,
		{
			peerPubkey: string;
			channelId: Buffer;
			payload: Buffer;
			deadline: number;
			timer: ReturnType<typeof setTimeout> | null;
		}
	> = new Map();
	/**
	 * HTLC settle operations deferred because their channel was quiescing
	 * when they were requested (BOLT 2: no update messages after stfu, issue
	 * 430). Drained when quiescence ends, after reestablish, and retried per
	 * block; purged on terminal states (they resolve on-chain). In-memory
	 * only: a restart re-derives settles from durable state via the node's
	 * recovery passes.
	 */
	private pendingQuiescentSettles: Map<
		string,
		Array<
			| { kind: 'fulfill'; htlcId: bigint; preimage: Buffer }
			| {
					kind: 'fail';
					htlcId: bigint;
					reason: Buffer;
					direction: HtlcDirection;
			  }
			| {
					kind: 'failMalformed';
					htlcId: bigint;
					sha256OfOnion: Buffer;
					failureCode: number;
			  }
		>
	> = new Map();
	private peerManager: PeerManager | null = null;
	private monitors: Map<string, ChainMonitor> = new Map();
	// Latest block height seen (for stamping when a force-close CPFP was broadcast).
	private _currentBlockHeight = 0;
	// Anchor force-close commitment CPFPs awaiting confirmation, keyed by channelId
	// hex. Retained so a stuck commitment package can be re-CPFP'd at a higher feerate
	// each block (reCpfpStuckCommitments) until the commitment reaches irrevocable depth.
	private _pendingCommitmentCpfp: Map<
		string,
		{
			action: IFeeBumpAndBroadcastChainAction;
			broadcastHeight: number;
			lastFeeRate: number;
			// Set when the last CPFP-child build/broadcast actually failed (e.g. no
			// confirmed wallet UTXOs). While true, reCpfpStuckCommitments retries next
			// cycle even at an unchanged feerate, so a CPFP is re-attempted once wallet
			// change confirms instead of being permanently blocked by the feerate gate.
			lastAttemptFailed?: boolean;
			// The tracked commitment has been seen CONFIRMED while this entry was
			// parked. If it ever reads unconfirmed again a reorg demoted it, and the
			// package may be out of the mempool entirely, so the next re-CPFP pass
			// skips the pacing gates instead of waiting them out (issue #578). Set
			// by the re-CPFP pass and by a report that demotes the record itself,
			// since a confirmation and its demotion can land between two passes.
			sawConfirmation?: boolean;
		}
	> = new Map();
	// Learned payment preimages, retained so monitors created later (on
	// force-close) can claim received HTLCs on-chain. Fed by recordPreimage().
	private _knownPreimages: Map<string, Buffer> = new Map();
	private zeroConfManager: ZeroConfManager = new ZeroConfManager();
	private _nextChannelIndex = 1;
	/** Wallet-owned destination for cooperative-close payouts, if configured. */
	private _walletDestinationScript: Buffer | null = null;
	/** Funding provider used to attach wallet inputs for anchor fee bumps. */
	private fundingProvider: IFundingProvider | null = null;
	/**
	 * Peer funding outpoints already submitted to verifyRemoteFundingInput,
	 * keyed per channel instance as `txidHex:vout` (issue #311). Dedups the
	 * chain queries an RBF's re-added inputs would repeat; bounded by the
	 * interactive-tx input and message caps.
	 */
	private _verifiedPeerInputs = new WeakMap<Channel, Set<string>>();
	/**
	 * Channels whose funding pledges were already released (issue #311 for
	 * v2 opens, issue #412 for v1). Several terminal sites can fire for one
	 * death (an ERROR action in the teardown batch plus the tx_abort
	 * finally, an error sweep plus a later disconnect); the provider release
	 * is idempotent, but releasing once keeps the call sites honest and
	 * observable.
	 */
	private _fundingPledgesReleased = new WeakSet<Channel>();
	/** Cached local node id (pubkey) for the tx_signatures ordering tie-break. */
	private localNodeIdCache: Buffer | null = null;
	/**
	 * A recovery-outbox supersede staged by handleRevokeAndAck for the batch
	 * it is about to process, consumed by processActions into that batch's
	 * persist request so the row deletions commit in the same transaction as
	 * the revoke's channel state (never eagerly, never on a failed persist).
	 */
	private _pendingOutboxSupersede: {
		channelIdHex: string;
		messageTypes: number[];
	} | null = null;
	/**
	 * Messages held behind the quorum barrier, keyed by channel. Per channel
	 * rather than node wide on purpose: one channel waiting on its frame must
	 * not stop an unrelated channel from sending, which is the section 9
	 * requirement that guardian latency not stall unrelated channels.
	 */
	private readonly barrierQueues = new Map<string, IBarrierQueue>();

	constructor(config: IChannelManagerConfig) {
		super();
		this.config = config;
	}

	/**
	 * Provide the wallet funding provider used to fund anchor fee bumps
	 * (zero-fee second-level HTLC txs and commitment CPFP). Without it, anchor
	 * fee-bump broadcasts fall back to broadcasting the unbumped transaction.
	 */
	setFundingProvider(fundingProvider: IFundingProvider | null): void {
		this.fundingProvider = fundingProvider;
	}

	/**
	 * Get the next channel index (for per-channel key derivation).
	 */
	get nextChannelIndex(): number {
		return this._nextChannelIndex;
	}

	/**
	 * Set the next channel index (e.g. after restoring from storage).
	 */
	set nextChannelIndex(value: number) {
		this._nextChannelIndex = value;
	}

	/**
	 * Derive per-channel keys for a new channel, or fall back to shared keys.
	 */
	private deriveKeysForNewChannel(): {
		basepoints: IChannelBasepoints;
		perCommitmentSeed: Buffer;
		fundingPrivkey: Buffer;
		htlcBasepointSecret?: Buffer;
		channelIndex: number;
	} {
		// The one place every brand-new channel passes through, and the one that
		// consumes a key index, so a refusal here cannot burn one. Every caller
		// already refuses ahead of this with a message scoped to its own
		// channel id, which is the better error; this is the backstop that
		// keeps a SIXTH entry point, written later, from silently opening a
		// channel into a namespace that can never record it. Restore does not
		// come through here (it derives from a recorded index via
		// getRecoveryChannelMaterial), so recovering an old channel is never
		// refused.
		this._assertNamespaceCanRecordANewChannel();
		if (this.config.channelKeyDeriver) {
			const idx = this._nextChannelIndex++;
			const keys = this.config.channelKeyDeriver(idx);
			return {
				basepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				fundingPrivkey: keys.fundingPrivkey,
				htlcBasepointSecret: keys.htlcBasepointSecret,
				channelIndex: idx
			};
		}
		return {
			basepoints: this.config.localBasepoints,
			perCommitmentSeed: this.config.localPerCommitmentSeed,
			fundingPrivkey: this.config.localFundingPrivkey,
			htlcBasepointSecret: this.config.htlcBasepointSecret,
			channelIndex: 0
		};
	}

	/**
	 * Construct the signer for a channel's keys: the injected signerFactory
	 * when configured (keys live out of process), else the in-process
	 * ChannelSigner over the raw key material.
	 */
	private makeSigner(
		channelKeyIndex: number,
		fundingPrivkey: Buffer,
		htlcBasepointSecret?: Buffer
	): ISigner {
		if (this.config.signerFactory) {
			return this.config.signerFactory(channelKeyIndex);
		}
		return new ChannelSigner(fundingPrivkey, htlcBasepointSecret);
	}

	/**
	 * Signer for an already-tracked channel: its own signer when set, else a
	 * fallback over the node-level keys (via the injected factory when
	 * configured). `includeHtlcSecret` preserves each call site's historical
	 * fallback shape — closing paths never needed HTLC keys.
	 */
	private signerFor(channel: Channel, includeHtlcSecret: boolean): ISigner {
		return (
			channel.getSigner() ||
			this.makeSigner(
				channel.channelKeyIndex ?? 0,
				this.config.localFundingPrivkey,
				includeHtlcSecret ? this.config.htlcBasepointSecret : undefined
			)
		);
	}

	/**
	 * Attach to a PeerManager to send/receive messages.
	 */
	attachToPeerManager(peerManager: PeerManager): void {
		this.peerManager = peerManager;

		const channelMsgTypes = [
			MessageType.OPEN_CHANNEL,
			MessageType.ACCEPT_CHANNEL,
			MessageType.FUNDING_CREATED,
			MessageType.FUNDING_SIGNED,
			MessageType.CHANNEL_READY,
			MessageType.UPDATE_ADD_HTLC,
			MessageType.UPDATE_FULFILL_HTLC,
			MessageType.UPDATE_FAIL_HTLC,
			MessageType.UPDATE_FAIL_MALFORMED_HTLC,
			MessageType.COMMITMENT_SIGNED,
			MessageType.REVOKE_AND_ACK,
			MessageType.UPDATE_FEE,
			MessageType.UPDATE_BLOCKHEIGHT,
			MessageType.SHUTDOWN,
			MessageType.CLOSING_SIGNED,
			MessageType.CLOSING_COMPLETE,
			MessageType.CLOSING_SIG,
			MessageType.CHANNEL_REESTABLISH,
			MessageType.STFU,
			MessageType.SPLICE,
			MessageType.SPLICE_ACK,
			MessageType.SPLICE_LOCKED,
			MessageType.START_BATCH,
			MessageType.OPEN_CHANNEL2,
			MessageType.ACCEPT_CHANNEL2,
			MessageType.TX_ADD_INPUT,
			MessageType.TX_ADD_OUTPUT,
			MessageType.TX_REMOVE_INPUT,
			MessageType.TX_REMOVE_OUTPUT,
			MessageType.TX_COMPLETE,
			MessageType.TX_SIGNATURES,
			MessageType.TX_INIT_RBF,
			MessageType.TX_ACK_RBF,
			MessageType.TX_ABORT,
			MessageType.ANNOUNCEMENT_SIGNATURES,
			// BOLT 1 error/warning: without these registrations a remote error is
			// silently dropped — the channel never gets marked ERRORED and the node
			// reconnect-loops against a peer that fails it on every reestablish.
			MessageType.ERROR,
			MessageType.WARNING
		];

		for (const type of channelMsgTypes) {
			peerManager.onMessage(type, (pubkey, msgType, payload) => {
				this.handleMessage(pubkey, msgType, payload);
			});
		}
	}

	/**
	 * Detach from the PeerManager.
	 */
	detachFromPeerManager(): void {
		this.peerManager = null;
		for (const timer of this.quiescenceTimers.values()) {
			clearTimeout(timer);
		}
		this.quiescenceTimers.clear();
		this._clearHeldUnknownReestablish();
	}

	// ─────────────── Zero-Conf Trusted Peers ───────────────

	/**
	 * Add a trusted peer for zero-conf channels.
	 */
	addTrustedPeer(pubkeyHex: string): void {
		this.zeroConfManager.addTrustedPeer(pubkeyHex);
	}

	/**
	 * Remove a trusted peer.
	 */
	removeTrustedPeer(pubkeyHex: string): void {
		this.zeroConfManager.removeTrustedPeer(pubkeyHex);
	}

	/**
	 * Check if a peer is trusted for zero-conf.
	 */
	isTrustedPeer(pubkeyHex: string): boolean {
		return this.zeroConfManager.isTrustedPeer(pubkeyHex);
	}

	/**
	 * List trusted peers.
	 */
	listTrustedPeers(): string[] {
		return this.zeroConfManager.listTrustedPeers();
	}

	/**
	 * Replace the set of peers whose JIT receive intent authorizes an OUTBOUND
	 * zero-conf open from us (issue #594). Separate from the trusted set, which
	 * is symmetric; see ZeroConfManager.setJitClients.
	 */
	setJitClients(pubkeyHexes: Iterable<string>): void {
		this.zeroConfManager.setJitClients(pubkeyHexes);
	}

	/** Is this peer a JIT client with a live receive intent? */
	isJitClient(pubkeyHex: string): boolean {
		return this.zeroConfManager.isJitClient(pubkeyHex);
	}

	/**
	 * Open a zero-conf channel with a peer.
	 * Peer must be in the trusted set.
	 *
	 * LOW-LEVEL, v1-ONLY primitive: this always sends a v1 open_channel and
	 * MUST NOT be called for a peer that negotiated option_dual_fund (BOLT 2
	 * forbids open_channel after that). Callers go through
	 * LightningNode.openChannel(..., trusted = true), which routes v1/v2 by
	 * the negotiated features; this stays public only for embedders and tests
	 * that drive v1 negotiation directly.
	 */
	openZeroConfChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint
	): Channel | null {
		if (!this.zeroConfManager.canOpenZeroConfTo(peerPubkey)) {
			this.emit('error', null, 'Peer is not trusted for zero-conf channels');
			return null;
		}
		// A finished namespace refuses a new channel through EVERY entry point,
		// and this one is a v1 primitive an embedder can still reach directly.
		// It matters most here: a zero-conf open sets minimumDepth 0 and
		// delivers push_msat in the INITIAL commitment, so nothing later in the
		// handshake is barrier-class and the whole capacity plus the push
		// reaches the chain on frames the guardians will never hold. Null
		// rather than a throw, matching this method's own disposition above.
		if (this._namespaceCannotRecordANewChannel()) {
			this.emit('error', null, NAMESPACE_LOST_REFUSAL);
			return null;
		}

		const chKeys = this.deriveKeysForNewChannel();
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis,
			pushMsat: pushMsat || 0n,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed
		});

		// Enable zero-conf
		state.zeroConfEnabled = true;
		state.trustedPeer = true;
		state.minimumDepth = 0;

		const signer = this.makeSigner(
			chKeys.channelIndex,
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		channel.channelKeyIndex = chKeys.channelIndex;
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const tempId = state.temporaryChannelId.toString('hex');
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);

		const actions = channel.initiateOpen(
			this.config.chainHash,
			this.config.preferAnchors,
			this.config.preferTaproot
		);
		this.processActions(peerPubkey, channel, actions);

		this.emit('channel:opened', channel.getTemporaryChannelId());
		return channel;
	}

	/**
	 * Open a new channel with a peer.
	 *
	 * opts.trusted opens a zero-conf channel: the zero_conf channel type goes
	 * on the wire and both sides fast-track channel_ready, so the channel is
	 * usable before the funding confirms. The peer must already be in the
	 * zero-conf trusted set. All other parameters (reserve included) stay
	 * standard BOLT 2.
	 */
	openChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint,
		beforeNegotiate?: (temporaryChannelId: Buffer) => void,
		opts?: { trusted?: boolean }
	): Channel {
		// Verify peer is connected before creating channel state
		if (this.peerManager && !this.peerManager.getPeer(peerPubkey)) {
			throw new Error(`Not connected to peer ${peerPubkey}`);
		}
		this._assertNamespaceCanRecordANewChannel();
		if (opts?.trusted && !this.zeroConfManager.canOpenZeroConfTo(peerPubkey)) {
			throw new Error(
				`Peer ${peerPubkey} is not in the trusted set; add it with addTrustedPeer (or let it register a JIT receive intent) before a trusted open`
			);
		}

		const chKeys = this.deriveKeysForNewChannel();
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis,
			pushMsat: pushMsat || 0n,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed
		});

		if (opts?.trusted) {
			state.zeroConfEnabled = true;
			state.trustedPeer = true;
			state.minimumDepth = 0;
		}

		const signer = this.makeSigner(
			chKeys.channelIndex,
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		channel.channelKeyIndex = chKeys.channelIndex;
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const tempId = state.temporaryChannelId.toString('hex');
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);

		// Give the caller its ONLY safe point to attach per-open state keyed by
		// the temporary channel id (the requested funding fee rate, a max-funding
		// marker). With a synchronous transport, the peer's accept_channel — and
		// therefore channel:accepted and auto-funding — fires INSIDE
		// processActions below, so state recorded only after this method returns
		// is recorded too late and the open funds with defaults. Only the id is
		// exposed: the caller has no business mutating the channel here.
		beforeNegotiate?.(state.temporaryChannelId);

		const actions = channel.initiateOpen(
			this.config.chainHash,
			this.config.preferAnchors,
			this.config.preferTaproot
		);
		this.processActions(peerPubkey, channel, actions);

		this.emit('channel:opened', channel.getTemporaryChannelId());
		return channel;
	}

	/**
	 * Tear down a negotiated-but-unfunded channel after local funding failed
	 * (buildFundingTransaction threw: insufficient funds, the max-funding
	 * mismatch guard). The channel is still keyed by its temporary id; without
	 * this it sits in SENT_OPEN/SENT_ACCEPT forever, the local channel list
	 * accumulates un-fundable entries, and the peer holds a half-open channel
	 * it will never see funded.
	 *
	 * Sends a BOLT 1 error for the temporary channel id so the peer forgets
	 * the channel, marks it ERRORED locally, removes it from the temp map, and
	 * emits channel:aborted. A no-op once the channel has been promoted to its
	 * permanent id (funding_created already went out; failing it here would be
	 * wrong) or was already cleaned up.
	 */
	abortPendingOpen(channel: Channel, reason: string): void {
		const tempIdBuf = channel.getTemporaryChannelId();
		const tempId = tempIdBuf?.toString('hex');
		if (!tempId || this.tempChannels.get(tempId) !== channel) return;
		// Temp-map membership alone does not prove the open is still pending:
		// handleAutoFunding's catch covers everything downstream of
		// buildFundingTransaction, and with a synchronous transport the whole
		// funding_created -> funding_signed -> permanent-map promotion chain
		// can run (and then a listener can throw) before createFunding unwinds
		// and deletes the temp entry. The reliable boundary is the permanent
		// channel id, which exists exactly from createFunding onward. Once
		// funding_created is out, BOLT 2 has switched the channel to that id
		// (a temp-id error would be misaddressed), and after funding_signed we
		// are obliged to broadcast — either way, no longer an abortable
		// pending open.
		if (channel.getChannelId()) return;
		const peerPubkey = this.channelPeers.get(tempId);
		channel.markErrored();
		if (!peerPubkey) {
			if (
				this.tempChannels.get(tempId) === channel &&
				!this.channelPeers.has(tempId)
			) {
				this.tempChannels.delete(tempId);
				this.emitContained('channel:aborted', tempIdBuf, reason);
			}
			return;
		}
		try {
			// Inside the guard, encoding included: the channel is already
			// ERRORED by here, so anything that throws on the way to the wire
			// must still leave the registration cleaned up and channel:aborted
			// emitted rather than stranding a failed channel in tempChannels.
			const wire = wireErrorPayloadFor(tempIdBuf, reason);
			if (wire) {
				this.sendMessage(peerPubkey, MessageType.ERROR, wire);
			}
		} finally {
			if (this.removeCurrentTempChannel(peerPubkey, channel)) {
				this.emitContained('channel:aborted', tempIdBuf, reason);
			}
		}
	}

	/**
	 * Create funding for a channel and send funding_created.
	 * Returns the permanent channel ID.
	 */
	createFunding(
		channel: Channel,
		fundingTxid: Buffer,
		fundingOutputIndex: number,
		signature: Buffer
	): Buffer | null {
		const peerPubkey = this.findPeerForChannel(channel);
		if (!peerPubkey) return null;
		const proposedChannelId = deriveChannelId(fundingTxid, fundingOutputIndex);
		if (
			!this.channelIdAvailableForLifecycle(
				proposedChannelId.toString('hex'),
				peerPubkey,
				channel
			)
		) {
			this.abortPendingOpen(
				channel,
				'Cannot create funding: channel_id is already in use'
			);
			return null;
		}

		// Sign the acceptor's initial commitment ourselves rather than trusting a
		// caller-supplied signature. The acceptor now verifies this signature in
		// handleFundingCreated (BOLT 2), so it must be a real signature over their
		// initial commitment (#0). Mirrors the acceptor-side signing in
		// handleFundingCreated above. Falls back to the passed signature only if
		// the remote's per-commitment point isn't available yet.
		const fundingState = channel.getFullState();
		fundingState.fundingTxid = fundingTxid;
		fundingState.fundingOutputIndex = fundingOutputIndex;
		let initialSignature = signature;
		let partialSignatureWithNonce: Buffer | undefined;
		if (fundingState.remoteCurrentPerCommitmentPoint) {
			const signer = this.signerFor(channel, true);
			if (isTaprootChannel(fundingState.channelType)) {
				// option_taproot: co-sign the acceptor's commitment #0 with a MuSig2
				// partial signature instead of ECDSA.
				partialSignatureWithNonce = this.signFundingPartial(
					fundingState,
					signer,
					fundingState.remoteCurrentPerCommitmentPoint
				);
			} else {
				const signed = signRemoteCommitment(
					fundingState,
					signer,
					fundingState.remoteCurrentPerCommitmentPoint
				);
				initialSignature = signed.signature;
			}
		}

		const actions = channel.createFundingCreated(
			fundingTxid,
			fundingOutputIndex,
			initialSignature,
			partialSignatureWithNonce
		);
		const channelId = channel.getChannelId();
		const hasError = actions.some(
			(action) => action.type === ChannelActionType.ERROR
		);
		const reservedId =
			channelId && !hasError ? channelId.toString('hex') : null;
		if (reservedId) this.channelIdReservations.set(reservedId, channel);
		try {
			this.processActions(peerPubkey, channel, actions);
			if (
				channelId &&
				!hasError &&
				!this.promoteChannelLifecycle(peerPubkey, channel)
			) {
				this.emitContained(
					'error',
					channelId,
					'Cannot promote funding: channel_id is already in use'
				);
				return null;
			}

			return channelId;
		} finally {
			if (
				reservedId &&
				this.channelIdReservations.get(reservedId) === channel
			) {
				this.channelIdReservations.delete(reservedId);
			}
		}
	}

	/**
	 * option_taproot: produce our 98-byte partial_signature_with_nonce over the
	 * peer's initial commitment (#0). We generate a fresh single-use SIGNING nonce
	 * here, combine it with the peer's VERIFICATION nonce (state.remoteNonce, from
	 * open_channel/accept_channel), and emit `partial(32) || pubSigningNonce(66)`.
	 * The signing nonce is used exactly once and then discarded.
	 */
	private signFundingPartial(
		state: IChannelState,
		signer: ISigner,
		remotePerCommitmentPoint: Buffer
	): Buffer {
		return this.signCommitmentPartial(
			state,
			signer,
			remotePerCommitmentPoint,
			0n
		);
	}

	/**
	 * option_taproot: produce our 98-byte partial_signature_with_nonce over the
	 * peer's commitment `commitmentNumber`. We generate a FRESH single-use SIGNING
	 * nonce and combine it with the peer's current VERIFICATION nonce
	 * (state.remoteNonce, seeded by channel_ready and rotated by each
	 * revoke_and_ack); the signing nonce is used exactly once and discarded.
	 * Returns `partial(32) || pubSigningNonce(66)`.
	 */
	private signCommitmentPartial(
		state: IChannelState,
		signer: ISigner,
		remotePerCommitmentPoint: Buffer,
		commitmentNumber: bigint
	): Buffer {
		if (!state.remoteNonce || state.remoteNonce.length !== 66) {
			throw new Error(
				'Cannot co-sign taproot commitment: missing peer verification nonce'
			);
		}
		const signingNonce = generateNonce({
			publicKey: state.localBasepoints.fundingPubkey,
			sessionId: crypto.randomBytes(32)
		});
		const partial = signRemoteCommitmentPartial(
			state,
			signer,
			signingNonce,
			state.remoteNonce,
			remotePerCommitmentPoint,
			commitmentNumber
		);
		return Buffer.concat([partial, Buffer.from(signingNonce)]);
	}

	/**
	 * Derive a ChannelResult from the actions a Channel returned.
	 *
	 * A Channel refuses an update by returning an ERROR action, not by throwing,
	 * so a wrapper that hardcodes ok:true reports every refusal as a success.
	 * That is how a forward whose outgoing add was refused (for want of outbound
	 * liquidity, or because the channel was no longer usable) still looked
	 * delivered to the node layer, which then never failed the incoming HTLC
	 * back. Callers already branch on ok; this makes the flag mean what they
	 * assume it means. Matches the shape used by initiateShutdown and forceClose.
	 */
	private resultFromActions(actions: ChannelAction[]): ChannelResult {
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		return { ok: true, actions };
	}

	/**
	 * Add an HTLC to a channel.
	 */
	addHtlc(
		channelId: Buffer,
		amountMsat: bigint,
		paymentHash: Buffer,
		cltvExpiry: number,
		onionRoutingPacket: Buffer,
		blindingPoint?: Buffer
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.addHtlc(
			amountMsat,
			paymentHash,
			cltvExpiry,
			onionRoutingPacket,
			blindingPoint
		);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: after sending update_add_htlc we must send commitment_signed so
		// the peer commits the HTLC. This kicks off the commitment exchange.
		// autoSignAndSendCommitment is a no-op if the add failed (needsCommitment
		// stays false), so an errored add does not trigger a commitment.
		if (channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
		return this.resultFromActions(actions);
	}

	/**
	 * Fulfill an HTLC on a channel.
	 */
	fulfillHtlc(
		channelId: Buffer,
		htlcId: bigint,
		preimage: Buffer
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// Structural fund-safety invariant (security finding C4): whenever we
		// settle an HTLC by revealing its preimage, deliver that preimage to the
		// chain monitors first. recordPreimage is idempotent, so callers that
		// already record (the node settle paths) cost nothing — but any future
		// settle path that forgets is covered here, making the C4 class of bug
		// (preimage learned but never wired to the monitor → on-chain loss)
		// structurally impossible rather than relying on every caller.
		const preimageHash = crypto.createHash('sha256').update(preimage).digest();
		this.recordPreimage(preimageHash, preimage);

		// BOLT 2 quiescence: no update messages after stfu (issue 430). The
		// preimage is already with the monitors (above); the wire half waits.
		if (
			this._deferSettleIfQuiescing(idHex, channel, {
				kind: 'fulfill',
				htlcId,
				preimage
			})
		) {
			return { ok: true, actions: [] };
		}

		const actions = channel.fulfillHtlc(htlcId, preimage);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: after sending update_fulfill_htlc, send commitment_signed to
		// commit the removal. autoSignAndSendCommitment is a no-op unless we owe a
		// commitment, so when the fulfill is already being driven reactively (via
		// handleRevokeAndAck) this does not double-commit.
		if (channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
		return this.resultFromActions(actions);
	}

	/**
	 * Fail a received HTLC on a channel. Direction defaults to RECEIVED; an
	 * offered id must be passed explicitly so channel.failHtlc can reject it
	 * rather than cancel an unrelated same-id received HTLC.
	 */
	failHtlc(
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer,
		direction: HtlcDirection = HtlcDirection.RECEIVED
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// BOLT 2 quiescence: no update messages after stfu (issue 430).
		if (
			this._deferSettleIfQuiescing(idHex, channel, {
				kind: 'fail',
				htlcId,
				reason,
				direction
			})
		) {
			return { ok: true, actions: [] };
		}

		const actions = channel.failHtlc(htlcId, reason, direction);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: after sending update_fail_htlc, send commitment_signed to commit
		// the removal. No-op unless we owe a commitment, so this does not
		// double-commit when the fail is already driven reactively.
		if (channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
		return this.resultFromActions(actions);
	}

	/**
	 * Fail a received HTLC with update_fail_malformed_htlc (BOLT 2). Used for
	 * unparseable onions and for invalid_onion_blinding at a non-introduction
	 * blinded hop (BOLT 4 route blinding).
	 */
	failMalformedHtlc(
		channelId: Buffer,
		htlcId: bigint,
		sha256OfOnion: Buffer,
		failureCode: number
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// BOLT 2 quiescence: no update messages after stfu (issue 430).
		if (
			this._deferSettleIfQuiescing(idHex, channel, {
				kind: 'failMalformed',
				htlcId,
				sha256OfOnion,
				failureCode
			})
		) {
			return { ok: true, actions: [] };
		}

		const actions = channel.failMalformedHtlc(
			htlcId,
			sha256OfOnion,
			failureCode
		);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: commit the removal, exactly as failHtlc.
		if (channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
		return this.resultFromActions(actions);
	}

	/**
	 * Sign and send commitment on a channel.
	 */
	signCommitment(
		channelId: Buffer,
		signature: Buffer,
		htlcSignatures: Buffer[]
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.signCommitment(signature, htlcSignatures);
		this.processActions(peerPubkey, channel, actions);
		return this.resultFromActions(actions);
	}

	/**
	 * Build, sign, and send commitment_signed for a channel.
	 * Called after any update message (fulfill, fail, add, fee) per BOLT 2.
	 */
	autoSignAndSendCommitment(channelId: Buffer): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			return { ok: false, actions: [], error: `Channel not found: ${idHex}` };
		}
		// BOLT 2: only send commitment_signed when we have pending updates the
		// remote has not yet committed. Re-committing an unchanged state would
		// loop the commitment exchange and reuse stale per-commitment points.
		if (!channel.needsCommitment()) {
			return { ok: true, actions: [] };
		}
		// Commitment-round alternation: never pipeline a second
		// commitment_signed while the previous one is unrevoked. The channel's
		// revocation bookkeeping binds each incoming revoke_and_ack to the one
		// outstanding commitment, and the reestablish retransmit cache holds a
		// single commitment_signed. needsCommitment stays set, so the deferred
		// signature goes out from the revoke_and_ack handler below.
		if (channel.isAwaitingRemoteRevocation()) {
			return { ok: true, actions: [] };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			return {
				ok: false,
				actions: [],
				error: `Peer not found for channel: ${idHex}`
			};
		}

		const signer = channel.getSigner();
		if (!signer) {
			return {
				ok: false,
				actions: [],
				error: 'No signer available for channel'
			};
		}

		const state = channel.getFullState();
		// Use the NEXT per-commitment point (for the next commitment we're signing)
		const perCommitPoint =
			state.remoteNextPerCommitmentPoint ||
			state.remoteCurrentPerCommitmentPoint;
		if (!perCommitPoint) {
			return {
				ok: false,
				actions: [],
				error: 'No remote per-commitment point'
			};
		}

		// Use next commitment number (current + 1) for post-update signing
		const nextCommitNum = state.remoteCommitmentNumber + 1n;

		let actions: ChannelAction[];
		if (isTaprootChannel(state.channelType)) {
			// option_taproot: co-sign the peer's next commitment with a MuSig2 partial
			// (fresh single-use signing nonce + peer's verification nonce), plus a
			// BIP340 Schnorr signature per HTLC second-level tx.
			const partial = this.signCommitmentPartial(
				state,
				signer,
				perCommitPoint,
				nextCommitNum
			);
			const htlcSigs = signRemoteHtlcSignaturesTaproot(
				state,
				signer,
				perCommitPoint,
				nextCommitNum
			);
			actions = channel.signCommitment(Buffer.alloc(64), htlcSigs, partial);
		} else {
			const { signature, htlcSignatures } = signRemoteCommitment(
				state,
				signer,
				perCommitPoint,
				nextCommitNum
			);
			if (channel.isSplicePendingLock()) {
				// Fully-signed splice awaiting its lock: every commitment update
				// signs BOTH active fundings (current + pending splice) and goes
				// out as a start_batch batch answered by one revoke_and_ack.
				const spliced = channel.getSplicedStateForSigning();
				if (!spliced) {
					return {
						ok: false,
						actions: [],
						error: 'Pending splice: spliced state unavailable for batch signing'
					};
				}
				const spliceSigned = signRemoteCommitment(
					spliced,
					signer,
					perCommitPoint,
					nextCommitNum
				);
				actions = channel.signCommitment(signature, htlcSignatures, undefined, {
					spliceSignature: spliceSigned.signature,
					spliceHtlcSignatures: spliceSigned.htlcSignatures
				});
			} else {
				actions = channel.signCommitment(signature, htlcSignatures);
			}
		}
		this.processActions(peerPubkey, channel, actions);
		return { ok: true, actions };
	}

	/**
	 * Initiate cooperative shutdown on a channel.
	 */
	initiateShutdown(
		channelId: Buffer,
		scriptPubkey: Buffer,
		acceptStaleStateRisk = false
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// Stamp the negotiation path from the init-feature intersection before
		// the state machine runs (its script rules depend on it).
		channel.setSimpleClose(this.peerNegotiatedSimpleClose(peerPubkey));

		const actions = channel.initiateShutdown(
			scriptPubkey,
			acceptStaleStateRisk
		);
		this.processActions(peerPubkey, channel, actions);
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		this.emit('channel:pending-close', channelId, 'local');
		return { ok: true, actions };
	}

	/**
	 * Update the fee rate on a channel (opener only).
	 */
	updateChannelFee(channelId: Buffer, feeratePerKw: number): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// BOLT 2 quiescence: update_fee is an update message too. Dropped, not
		// deferred: fee refresh is periodic and idempotent, the next cycle
		// re-proposes once the session ends.
		if (typeof channel.isQuiescing === 'function' && channel.isQuiescing()) {
			return {
				ok: false,
				actions: [],
				error: 'Cannot update fee: channel is quiescing'
			};
		}

		const actions = channel.updateFee(feeratePerKw);
		this.processActions(peerPubkey, channel, actions);
		// Check for errors in actions
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}

		// BOLT 2: update_fee only takes effect once committed. Like the HTLC
		// update paths, we must follow it with commitment_signed so the new
		// feerate is actually committed (promoted from pendingFeeratePerKw on
		// revoke_and_ack). Without this the fee stays staged forever, and the
		// next commitment built at the uncommitted feerate desyncs against the
		// peer — producing "invalid commitment signature" on the next HTLC.
		// autoSignAndSendCommitment is a no-op unless we owe a commitment.
		if (channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
		return { ok: true, actions };
	}

	/**
	 * Provide the caller-owed tx_signatures witnesses for a v2 open: the
	 * public answer to channel:txsigs-needed (issue 307). During the live
	 * exchange the channel still lives in the temporary map (promotion
	 * happens once the open leaves AWAITING_TX_SIGNATURES) while the event
	 * carries the PERMANENT id, so the lookup covers both maps; getChannel
	 * alone cannot resolve it inside the notification callback. Dispatches
	 * the resulting actions (persist, wire send, funding watch) through the
	 * normal action path and promotes a completed exchange, mirroring the
	 * inbound tx_signatures handler.
	 */
	provideTxSignatures(
		channelId: Buffer,
		txid: Buffer,
		outputIndex: number,
		witnesses: Buffer[][]
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel =
			this.channels.get(idHex) ?? this.findChannelByChannelIdInTemp(channelId);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		// A temp-resident channel's peer binding is keyed by its temporary id.
		const peerPubkey =
			this.channelPeers.get(idHex) ??
			this.channelPeers.get(channel.getTemporaryChannelId().toString('hex'));
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.sendTxSignatures(txid, outputIndex, witnesses);
		this.processActions(peerPubkey, channel, actions);
		this._promoteV2ChannelIfReady(peerPubkey, channel);
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		return { ok: true, actions };
	}

	/**
	 * Deliver a third-party input owner's witness for an EXTERNAL funding
	 * input of a v2 open (issue #572): the out-of-band answer to the
	 * externalInputIndices half of channel:txsigs-needed. The channel
	 * validates the witness against the recorded prevouts before storing it,
	 * and the last delivery releases our withheld tx_signatures. The same
	 * dual-map lookup as provideTxSignatures applies: during the live
	 * exchange the channel may still be temp-resident while the signal
	 * carries the PERMANENT id. Promotion after dispatch keeps the fork's
	 * promote-on-ready guarantee (97df373): when the peer signed first, this
	 * flush is the last step of the open and the channel must leave the temp
	 * map before its early channel_ready or confirmation dispatch arrives.
	 */
	provideV2ExternalWitness(
		channelId: Buffer,
		prevTxid: Buffer,
		prevOutputIndex: number,
		witness: Buffer[]
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel =
			this.channels.get(idHex) ?? this.findChannelByChannelIdInTemp(channelId);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		// A temp-resident channel's peer binding is keyed by its temporary id.
		const peerPubkey =
			this.channelPeers.get(idHex) ??
			this.channelPeers.get(channel.getTemporaryChannelId().toString('hex'));
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		let actions: ChannelAction[];
		try {
			actions = channel.provideV2ExternalWitness(
				prevTxid,
				prevOutputIndex,
				witness
			);
		} catch (err) {
			// The channel throws WITHOUT touching state: a refusal of the
			// caller's delivery, not a channel failure. Nothing to dispatch
			// and no 'error' event (the initiateFundingRbf refusal
			// convention); the caller retries with a correct witness.
			return { ok: false, actions: [], error: (err as Error).message };
		}
		// The caller's obligation to the input owner is discharged by the
		// tx_signatures this release sends, not by the channel accepting the
		// witness, so a dispatch that stopped short of the wire has to reach it.
		const progress = newDispatchProgress();
		this.processActions(peerPubkey, channel, actions, progress);
		this._promoteV2ChannelIfReady(peerPubkey, channel);
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		return {
			ok: true,
			actions,
			sendsWithheld:
				progress.sendsWithheld ||
				progress.sendsHeld ||
				this._txSignaturesStillHeld(channel)
		};
	}

	/**
	 * Deliver a third-party input owner's witness for an EXTERNAL input of a
	 * splice-in (issue #592): the answer to channel:splice-txsigs-needed. The
	 * channel validates the witness against the recorded prevouts before
	 * storing it, and the last delivery releases our withheld tx_signatures,
	 * which is what makes the splice broadcastable. Permanent map only: a
	 * splice exists only on an established channel.
	 */
	provideSpliceExternalWitness(
		channelId: Buffer,
		prevTxid: Buffer,
		prevOutputIndex: number,
		witness: Buffer[]
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		let actions: ChannelAction[];
		try {
			actions = channel.provideSpliceExternalWitness(
				prevTxid,
				prevOutputIndex,
				witness
			);
		} catch (err) {
			// The channel throws WITHOUT touching state: a refusal of the
			// caller's delivery, not a channel failure. Nothing to dispatch and
			// no 'error' event (the initiateFundingRbf refusal convention); the
			// caller retries with a correct witness.
			return { ok: false, actions: [], error: (err as Error).message };
		}
		const progress = newDispatchProgress();
		this.processActions(peerPubkey, channel, actions, progress);
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		return {
			ok: true,
			actions,
			sendsWithheld:
				progress.sendsWithheld ||
				progress.sendsHeld ||
				this._txSignaturesStillHeld(channel)
		};
	}

	/**
	 * Handle peer disconnection: mark all channels with this peer as AWAITING_REESTABLISH.
	 */
	handlePeerDisconnected(peerPubkey: string): void {
		// A parked reestablish (issue #462) describes a connection that is now
		// gone, so its timer is retired. The entry stays with its ORIGINAL
		// deadline: the peer that reconnects and re-sends gets what is left of
		// the one window it was granted, not another one.
		for (const entry of this.heldUnknownReestablish.values()) {
			if (entry.peerPubkey !== peerPubkey || !entry.timer) continue;
			clearTimeout(entry.timer);
			entry.timer = null;
		}
		// Established channels → mark for reestablish
		for (const channel of this.getChannelsByPeer(peerPubkey)) {
			// Anything held behind the quorum barrier goes FIRST, and is
			// dropped rather than flushed. markForReestablish rolls the channel
			// backward under it: uncommitted received HTLCs are deleted and
			// their balance credited back, offered HTLCs are un-fulfilled and
			// un-failed, an uncommitted fee update is rolled back and the
			// splice driver is reset. A held message describes the view before
			// all of that, so releasing it later would put a description of
			// state this channel no longer has onto the wire. What is
			// retransmittable comes back through the outbox and the reestablish
			// rules; what is not was a negotiation that restarts.
			const channelIdHex = channel.getChannelId()?.toString('hex');
			if (channelIdHex) this.purgeBarrierQueue(channelIdHex);
			// A promoted v1 opener still awaiting funding_signed has no
			// commitment to resume: BOLT 2 has no reestablish before
			// funding_signed, and the peers (eclair, LND) forget the attempt
			// on disconnect. markForReestablish does nothing for this state,
			// so without this arm the channel sat in the permanent map
			// forever and its funding pledges renewed for the life of the
			// process (issue #412). Drop the whole lifecycle and free the
			// inputs; the channel object keeps its historical state, exactly
			// as a refused funding_signed leaves it.
			if (
				channel.getState() === ChannelState.SENT_FUNDING_CREATED &&
				channel.getFullState().fundingVersion !== 2
			) {
				this.removeCurrentChannelLifecycle(peerPubkey, channel);
				this.emit(
					'error',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					'Peer disconnected during channel open (state: SENT_FUNDING_CREATED)'
				);
				this.releaseRefusedV1FundingPledges(channel);
				continue;
			}
			this._rollbackForReestablish(channel);
			// Quiescence never survives a disconnect (BOLT 2); retire the
			// watchdog and release anything parked behind the session.
			this._syncQuiescenceWatchdog(channel);
			// The disconnect dropped any un-acked RBF request; coins selected
			// to raise its contribution are free again.
			this.releaseDanglingV2Pledges(channel);
			// A dead unfunded v2 open: either the drop branch just abandoned
			// a committed RBF renegotiation nothing was signed for, or the
			// channel was already ERRORED by an abort whose echo never
			// arrived. Remove it entirely, mirroring the restart path (which
			// deletes the row). Leaving it ERRORED left a silent permanent
			// channel that no reestablish, disposition or cleanup ever
			// touches; a peer that still asks after removal gets the
			// unknown-channel error and ends the attempt on its side.
			//
			// Not for a record this process only read off disk: nothing has
			// checked it against the peer or the chain, and a restore can hand
			// back an older view of an open that has since funded. Such a
			// channel is retained here and removed, if it really is dead, by
			// the funding-missing watchdog, which asks the chain and then waits
			// out BOLT 2's 2016 blocks (issue #463).
			if (
				channel.isAbandonedV2Open() &&
				channelIdHex &&
				!channel.isRecordRestoredFromDisk()
			) {
				this.channels.delete(channelIdHex);
				this.channelPeers.delete(channelIdHex);
				this.emit(
					'channel:abandoned',
					channel.getChannelId(),
					'dead unfunded v2 open removed on disconnect'
				);
				this.releaseAbandonedV2Pledges(channel);
			}
		}

		// Early-stage channels → abort (BOLT 2: no reestablish before
		// funding_signed for v1; before the initial commitment_signed for v2)
		const earlyStates = new Set([
			ChannelState.NONE,
			ChannelState.SENT_OPEN,
			ChannelState.SENT_ACCEPT,
			ChannelState.SENT_FUNDING_CREATED,
			ChannelState.DUAL_FUNDING_V2,
			ChannelState.AWAITING_TX_SIGNATURES
		]);

		for (const [tempId, channel] of this.tempChannels) {
			if (this.channelPeers.get(tempId) !== peerPubkey) continue;
			const state = channel.getState();
			// A dead unfunded v2 open still in the temp map: it errored as
			// the tx_abort responder and the aborting peer disconnected
			// before this side ever heard back. ERRORED is not an early
			// state, so the sweep below skipped it forever. Remove it and
			// let the node delete any row via channel:abandoned.
			if (channel.isAbandonedV2Open()) {
				this.tempChannels.delete(tempId);
				this.channelPeers.delete(tempId);
				this.emit(
					'channel:abandoned',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					'dead unfunded v2 open removed on disconnect'
				);
				this.releaseAbandonedV2Pledges(channel);
				continue;
			}
			if (!earlyStates.has(state)) continue;

			// A v2 open past its point of no return (the durable record exists)
			// is NOT abortable: BOLT 2 requires the signature exchange to
			// resume over reestablish. The promotion normally happened with the
			// batch that created the record; catch any channel the disconnect
			// beat to it, then treat it like the established loop above.
			if (channel.getFullState().v2InFlight != null) {
				this._promoteV2ChannelIfReady(peerPubkey, channel);
				const idHex = channel.getChannelId()?.toString('hex');
				if (idHex && this.channels.has(idHex)) {
					this.purgeBarrierQueue(idHex);
					this._rollbackForReestablish(channel);
					this.releaseDanglingV2Pledges(channel);
					continue;
				}
			}

			channel.getFullState().state = ChannelState.ERRORED;
			this.tempChannels.delete(tempId);
			this.channelPeers.delete(tempId);
			this.emit(
				'error',
				channel.getTemporaryChannelId(),
				`Peer disconnected during channel open (state: ${state})`
			);
			// A live record-less v2 negotiation died with its peer: nothing
			// was ever signed, so its funding pledges release at once
			// (issue #311). The getter answers empty for the v1 states in
			// this sweep.
			this.releaseAbandonedV2Pledges(channel);
		}
	}

	/**
	 * Handle peer reconnection: send channel_reestablish for all peer channels.
	 */
	handlePeerReconnected(peerPubkey: string): void {
		for (const channel of this.getChannelsByPeer(peerPubkey)) {
			if (channel.getState() === ChannelState.AWAITING_REESTABLISH) {
				const actions = channel.createReestablish();
				this.processActions(peerPubkey, channel, actions);
			} else if (channel.getState() === ChannelState.ERRORED) {
				// Recovery 5.6 liveness: the peer-close request survives
				// crashes as a persisted disposition, not as a wire message.
				// Repeat it on every reconnect until the peer's force close
				// resolves the channel on chain; empty for ordinary errors.
				const actions = channel.buildRecoveryCloseActions();
				if (actions.length > 0) {
					this.processActions(peerPubkey, channel, actions);
				}
			}
		}
	}

	/**
	 * Send the durable peer-close request NOW, rather than waiting for the
	 * next reconnect to regenerate it (recovery 5.6 liveness).
	 *
	 * handlePeerReconnected repeats the request on every reconnect, which
	 * covers a crash between the ERRORED persist and the socket. It does not
	 * cover a channel that reaches the held ERRORED state while the peer is
	 * ALREADY connected, which is the ordinary case for a capsule-restored
	 * channel the peer errors: nothing automatic will close it, and without
	 * this both sides would sit waiting on each other until something else
	 * happens to reconnect them (issue #469).
	 *
	 * Returns whether a request was actually sent; empty for a channel with no
	 * recovery-close disposition, which is every ordinary error.
	 */
	sendRecoveryCloseRequest(channelId: Buffer): boolean {
		const idHex = channelId.toString('hex');
		const channel = this.getChannel(channelId);
		const peerPubkey = this.channelPeers.get(idHex);
		if (!channel || !peerPubkey) return false;
		if (channel.getState() !== ChannelState.ERRORED) return false;
		const actions = channel.buildRecoveryCloseActions();
		if (actions.length === 0) return false;
		this.processActions(peerPubkey, channel, actions);
		return true;
	}

	/**
	 * markForReestablish plus the report its rollback owes the node.
	 *
	 * Deferred out of this turn, exactly as the deferred-settle drain is: at
	 * startup this runs from restoreChannel, and the node's forwarding
	 * linkages, payment records and htlc-to-payment map are all loaded AFTER
	 * the channels are, so a synchronous emit would look them up before they
	 * exist. The durable backstops behind it (the owed-upstream pass, and the
	 * stuck-payment sweep) cover a crash in between, so nothing here needs a
	 * persisted marker of its own.
	 */
	private _rollbackForReestablish(channel: Channel): void {
		// A row already wrapped in AWAITING_REESTABLISH gets the unsigned-add
		// rollback WITHOUT being re-wrapped: markForReestablish refuses that
		// state on purpose, because wrapping it again would overwrite
		// preReestablishState with AWAITING_REESTABLISH and lose the state the
		// channel is meant to return to. A capsule can hold exactly such a row,
		// and without this the add it carries survives to be replayed (issue
		// #469).
		const abandoned =
			channel.getState() === ChannelState.AWAITING_REESTABLISH
				? channel.dropUnsignedHeldAdds()
				: channel.markForReestablish();
		if (abandoned.length === 0) return;
		const channelId = channel.getChannelId() ?? channel.getTemporaryChannelId();
		setImmediate(() => {
			this.emit('htlc:local-add-abandoned', channelId, abandoned);
		});
	}

	/**
	 * Restore a channel from persisted state.
	 * Channels in NORMAL state are transitioned to AWAITING_REESTABLISH
	 * since we need to send channel_reestablish before resuming operations.
	 *
	 * @param keyIndex - If provided and channelKeyDeriver exists, re-derives
	 *   per-channel keys instead of using shared global keys.
	 * @param perChannelKeys - Key material ALREADY derived for `keyIndex` (see
	 *   getRecoveryChannelMaterial). Passing it keeps the deriver, a caller
	 *   supplied callback, to a single evaluation per channel, so the state's
	 *   basepoints and the signer's secrets cannot come from two different
	 *   answers. Omit it and the deriver is called here, as before.
	 */
	restoreChannel(
		channel: Channel,
		peerPubkey: string,
		keyIndex?: number | null,
		perChannelKeys?: IPerChannelKeys | null
	): void {
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		const channelId = channel.getChannelId();
		if (channelId) {
			// Wire signer — use per-channel keys when available
			let fundingPrivkey = this.config.localFundingPrivkey;
			let htlcBasepointSecret = this.config.htlcBasepointSecret;

			// 0 is the node-level shared-key signer; a per-channel restore
			// replaces it with the channel's own index below.
			let signerKeyIndex = 0;
			if (
				keyIndex != null &&
				(perChannelKeys || this.config.channelKeyDeriver)
			) {
				const keys = perChannelKeys ?? this.config.channelKeyDeriver!(keyIndex);
				fundingPrivkey = keys.fundingPrivkey;
				htlcBasepointSecret = keys.htlcBasepointSecret;
				// Preserve key index on channel for future persists
				channel.channelKeyIndex = keyIndex;
				// Advance _nextChannelIndex past any restored index
				if (keyIndex >= this._nextChannelIndex) {
					this._nextChannelIndex = keyIndex + 1;
				}
				signerKeyIndex = keyIndex;
			}

			const signer = this.makeSigner(
				signerKeyIndex,
				fundingPrivkey,
				htlcBasepointSecret
			);
			channel.setSigner(signer);

			// Rebuild the in-memory splice session/driver for a persisted in-flight
			// splice BEFORE markForReestablish, so the splice survives the
			// reconnect handling (markForReestablish keeps it only when present).
			channel.restoreSpliceInFlight();
			// Same for a v2 open past its initial commitment_signed: rebuild the
			// builder-less session from the durable record so the signature
			// exchange resumes over channel_reestablish.next_funding.
			channel.restoreV2InFlight();
			// And refuse to resume one whose commitment #0 has no outputs to
			// broadcast, while our witnesses can still keep the funding off
			// chain (issue #387). The disposal is in memory only, so it is
			// reported for the node to persist: without that the unsafe row
			// stays on disk as AWAITING_TX_SIGNATURES and is resurrected on
			// every restart, and an ERRORED channel is never reconnected, so
			// nothing else would ever clean it up.
			const disposition = channel.refuseUnviableV2InFlight();
			// Rows written before the open sites derived the enforced reserve
			// carry the configured static value forever (issues #381, #387).
			// Lower it to what their capacity prices. Derived from the row alone,
			// never from this node's current configuration: that configuration is
			// mutable between runs, and a row is not less broken because the
			// operator has since changed it.
			channel.repairEnforcedChannelReserve();
			// And the mirror: the reserve a v2 row KEEPS was never negotiated,
			// so a row that predates the derivation carries the configured
			// constant, which above 1,000,000 sat is LESS than the peer
			// requires of us. Raise it (issue #387).
			channel.repairKeptChannelReserve();

			// Mark channels for reestablishment — after a restart the peer
			// connection is lost, so we must complete channel_reestablish
			// before resuming normal operations (BOLT 2 §5).
			const st = channel.getState();
			if (
				st === ChannelState.NORMAL ||
				st === ChannelState.AWAITING_FUNDING_CONFIRMED ||
				st === ChannelState.AWAITING_CHANNEL_READY ||
				st === ChannelState.SHUTTING_DOWN ||
				// A close under negotiation must complete channel_reestablish
				// before it resumes, exactly like any other operational state,
				// and markForReestablish has always handled it; only this list
				// left it out. A held channel makes the omission matter: it
				// sends no reestablish, so it never reaches its timeout either.
				st === ChannelState.NEGOTIATING_CLOSING ||
				// Already wrapped by the session that persisted it. It is not
				// re-wrapped, but it still owes the unsigned-add rollback.
				st === ChannelState.AWAITING_REESTABLISH ||
				st === ChannelState.SPLICING ||
				// A v2 open is only reestablishable when the durable record made
				// it resumable; a row persisted before the record existed keeps
				// its legacy shape (an inert AWAITING_TX_SIGNATURES orphan, and
				// the quorum startup guard still gets to see it). DUAL_FUNDING_V2
				// rows never reach here: they are RBF-renegotiation residue and
				// the node removes them durably before restoring channels.
				(st === ChannelState.AWAITING_TX_SIGNATURES &&
					channel.getFullState().v2InFlight != null)
			) {
				this._rollbackForReestablish(channel);
			}
			this.channels.set(channelId.toString('hex'), channel);
			this.channelPeers.set(channelId.toString('hex'), peerPubkey);
			// Reported only now: a listener persists the disposal, and both the
			// channel and its peer mapping have to be registered before it can.
			if (disposition !== 'none') {
				this.emit('channel:v2-open-disposed', channelId, disposition);
				this.emit(
					'error',
					channelId,
					disposition === 'refused'
						? 'v2 open refused on restore: commitment #0 has no broadcastable output'
						: 'v2 open replacement abandoned on restore: commitment #0 has no broadcastable output'
				);
			}
			// This channel came from persistence, so the node-level state that
			// would resolve its committed inbound HTLCs (MPP part sets, held
			// forwards, the forwarding machinery's view) died with the previous
			// process. Arm the one-shot repair; reestablish fires it.
			this.channelsAwaitingRestoreRepair.add(channelId.toString('hex'));
		}
	}

	/**
	 * Register a channel as one whose record came off disk at startup.
	 *
	 * Called by the node's storage restore ONLY. Deliberately not inside
	 * restoreChannel, which is also the live re-restore path for a blocked
	 * persist resync and for both abandonment reverts: those re-read a row
	 * this process itself negotiated, and marking them would disable the
	 * removals that keep dead opens from accumulating.
	 */
	markChannelRestoredFromDisk(channelId: Buffer): void {
		this.channels.get(channelId.toString('hex'))?.markRecordRestoredFromDisk();
	}

	/**
	 * Whether this channel's record was loaded from disk at startup and has
	 * therefore never been checked against anything but itself. Callers that
	 * would DELETE a channel on a local inference must refuse while this is
	 * true and let the chain answer instead (issue #463).
	 */
	isChannelRestoredFromDisk(channelId: Buffer): boolean {
		return (
			this.channels
				.get(channelId.toString('hex'))
				?.isRecordRestoredFromDisk() ?? false
		);
	}

	/**
	 * Get the peer pubkey for a channel.
	 */
	getPeerForChannel(channelId: Buffer): string | undefined {
		return this.channelPeers.get(channelId.toString('hex'));
	}

	/**
	 * Get a channel by its channel ID (checks both permanent and temp maps).
	 */
	getChannel(channelId: Buffer): Channel | undefined {
		const hex = channelId.toString('hex');
		return this.channels.get(hex) || this.tempChannels.get(hex);
	}

	/**
	 * Get a temp channel by its temporary channel ID.
	 */
	getTempChannel(tempChannelId: Buffer): Channel | undefined {
		return this.tempChannels.get(tempChannelId.toString('hex'));
	}

	/**
	 * Get all channels for a specific peer.
	 */
	getChannelsByPeer(peerPubkey: string): Channel[] {
		const result: Channel[] = [];
		for (const [id, channel] of this.channels) {
			if (this.channelPeers.get(id) === peerPubkey) {
				result.push(channel);
			}
		}
		return result;
	}

	/**
	 * List all channels (including pending opens in tempChannels).
	 */
	listChannels(): Channel[] {
		return [...this.channels.values(), ...this.tempChannels.values()];
	}

	/**
	 * Distinct pubkeys of every peer we track a channel with, pending opens
	 * included.
	 */
	listChannelPeers(): string[] {
		return [...new Set(this.channelPeers.values())];
	}

	/**
	 * Notify that a funding transaction has been confirmed.
	 * `confirmedTxidHex` (display byte order) names WHICH candidate reached
	 * depth when the watcher tracks several (post-signatures RBF); omitted
	 * means the channel's current funding tx.
	 */
	handleFundingConfirmed(channelId: Buffer, confirmedTxidHex?: string): void {
		const channel = this.channels.get(channelId.toString('hex'));
		if (!channel) return;

		const peerPubkey = this.channelPeers.get(channelId.toString('hex'));
		if (!peerPubkey) return;

		const confirmedTxid = confirmedTxidHex
			? Buffer.from(confirmedTxidHex, 'hex').reverse()
			: undefined;
		const actions = channel.fundingConfirmed(confirmedTxid);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * Resolve the per-channel on-chain signing secrets for a channel's monitor.
	 *
	 * Channels opened with a per-channel key deriver hold basepoints that are NOT
	 * the node-level base secrets, so on-chain claims — our to_remote on a remote
	 * force-close, plus to_local/HTLC sweeps on our own commitment — must be signed
	 * with the channel's own keys. Returns null for channels created without
	 * per-channel keys, in which case callers fall back to node-level base secrets.
	 */
	private perChannelMonitorKeys(channel: Channel | undefined): {
		revocationBasepointSecret: Buffer;
		paymentBasepointSecret: Buffer;
		delayedPaymentBasepointSecret?: Buffer;
		htlcBasepointSecret?: Buffer;
	} | null {
		const keyIndex = channel?.channelKeyIndex;
		if (!this.config.channelKeyDeriver || keyIndex == null) return null;
		const k = this.config.channelKeyDeriver(keyIndex);
		if (!k.revocationBasepointSecret || !k.paymentBasepointSecret) return null;
		return {
			revocationBasepointSecret: k.revocationBasepointSecret,
			paymentBasepointSecret: k.paymentBasepointSecret,
			delayedPaymentBasepointSecret: k.delayedPaymentBasepointSecret,
			htlcBasepointSecret: k.htlcBasepointSecret
		};
	}

	/**
	 * Resolve per-channel monitor signing secrets by channel ID (used by the node
	 * when restoring persisted monitors). Returns null when per-channel keys are
	 * not in use for the channel.
	 */
	getMonitorSigningKeys(channelId: Buffer): {
		revocationBasepointSecret: Buffer;
		paymentBasepointSecret: Buffer;
		delayedPaymentBasepointSecret?: Buffer;
		htlcBasepointSecret?: Buffer;
	} | null {
		return this.perChannelMonitorKeys(
			this.channels.get(channelId.toString('hex'))
		);
	}

	/**
	 * Resolve the LOCAL key material for a channel being reconstructed from a
	 * static channel backup: the per-channel deriver keys for a non-null
	 * channelKeyIndex, or the node-level basepoints for legacy channels. Also
	 * returns the local channel config the manager would use for a new channel.
	 * Never advances the next-channel index (restoreChannel handles that).
	 *
	 * `perChannelKeys` is the deriver's WHOLE answer, returned so the caller
	 * can hand it back to restoreChannel: the reconstructed state's
	 * basepoints and the signer's secrets then provably come from ONE
	 * evaluation of the callback, rather than two that a non-deterministic
	 * implementation could answer differently.
	 */
	getRecoveryChannelMaterial(channelKeyIndex: number | null): {
		basepoints: IChannelBasepoints;
		perCommitmentSeed: Buffer;
		localConfig: IChannelConfig;
		perChannelKeys: IPerChannelKeys | null;
	} {
		if (this.config.channelKeyDeriver && channelKeyIndex != null) {
			const keys = this.config.channelKeyDeriver(channelKeyIndex);
			return {
				basepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
				perChannelKeys: keys
			};
		}
		return {
			basepoints: this.config.localBasepoints,
			perCommitmentSeed: this.config.localPerCommitmentSeed,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			perChannelKeys: null
		};
	}

	/**
	 * Update the sweep destination on every existing chain monitor. Used when a
	 * wallet-owned sweep address becomes available after startup, so pending
	 * force-close recoveries redirect to the wallet instead of the funding key.
	 */
	setMonitorDestinationScript(destinationScript: Buffer): void {
		this._walletDestinationScript = destinationScript;
		for (const monitor of this.monitors.values()) {
			monitor.setDestinationScript(destinationScript);
		}
	}

	/**
	 * Force close a channel by broadcasting the latest local commitment.
	 */
	forceClose(
		channelId: Buffer,
		destinationScript: Buffer,
		feeRatePerVbyte = 10,
		network?: import('bitcoinjs-lib').Network
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const signer = this.signerFor(channel, true);
		// PLAN, then abandon, then APPLY. The order is the whole point.
		//
		// A force close is the operator's exit and must not queue behind a
		// barrier that may never release: its batch carries no persist, so the
		// wire-order rule would park it behind whatever this channel is already
		// holding, and a refusal there would suppress the commitment broadcast
		// while the CHANNEL_CLOSED beside it still ran and this method still
		// answered ok. But abandoning the queue is irreversible, and a close
		// legitimately refuses for several reasons (an uncertain or stale
		// restored state, a missing remote signature or taproot nonce, a splice
		// it cannot adopt), so it cannot be done first either: a REFUSED close
		// would consume the very batch it was meant to replace, including a
		// held recovery declaration.
		//
		// Planning separates the two. Everything that can refuse happens before
		// the queue is touched and before the channel moves; once the plan is
		// ready nothing is left that can decline, so ending the off-chain
		// protocol and preserving off-chain order behind an unreachable quorum
		// are no longer in tension.
		//
		// The channel holds no monitor, so the fact only this side knows travels
		// with the request: a CLOSED channel whose recorded mutual close is
		// already on chain has no dead end to rescue (issue #622). A restored
		// monitor cannot say which it is until its watch reports, and travels as
		// that third answer rather than as a no.
		const existingMonitor = this.monitors.get(idHex);
		const fundingSpendConfirmed =
			existingMonitor !== undefined && existingMonitor.isCommitmentConfirmed();
		const fundingSpendReverifyPending =
			existingMonitor !== undefined &&
			existingMonitor.isCommitmentReverifyPending();
		const plan = channel.prepareForceClose(signer, {
			fundingSpendConfirmed,
			fundingSpendReverifyPending
		});
		if (!plan.ok) {
			this.emit('error', channelId, plan.error);
			return {
				ok: false,
				actions: [
					{ type: ChannelActionType.ERROR, message: plan.error }
				] as ChannelAction[],
				error: plan.error
			};
		}

		// Detach, apply, dispatch, THEN settle. Nothing between the plan and
		// its application may run a listener: an observer that throws would
		// leave the queue gone and the close never applied, and one that
		// synchronously re-enters this manager would move the channel out from
		// under a commitment already built against it. So the teardown is
		// split, and only its callback-free half runs in that gap.
		const detached = this._detachQueueForTerminalClose(idHex);
		const actions = channel.applyForceClosePlan(plan);
		const peerPubkey = this.channelPeers.get(channelId.toString('hex'));
		if (peerPubkey) {
			this._dispatchTerminalForceClose(peerPubkey, channel, actions);
		}
		// What the detached batches still owed, with their wire half suppressed
		// and every observer failure contained. After the dispatch above, so a
		// listener re-entering this channel meets a FORCE_CLOSED one.
		this._settleDetachedQueueAfterTerminalClose(idHex, detached);
		this.emit('channel:force-closing', channelId, 'local');

		const state = channel.getFullState();

		// Anchor channels: the commitment is broadcast at a low feerate, so attach
		// a wallet-funded CPFP child spending our local anchor to speed confirmation.
		this._maybeCpfpAnchorCommitment(channelId, state, actions, feeRatePerVbyte);

		// A fresh monitor starts blank: no tracked outputs, no classification and
		// no irrevocable-depth clock. Handing one to a channel whose funding spend
		// is already CONFIRMED destroys the record of the transaction that
		// actually settled and leaves the replacement waiting on a commitment that
		// can never confirm, so the close never resolves and the watch is never
		// retired (issue #622). Keep the existing monitor instead, aiming its
		// sweeps at this call's destination.
		//
		// An adoption is the exception: the plan moved the close onto a NEW
		// funding outpoint, so the confirmed spend the monitor recorded belongs to
		// the outpoint the channel just left and a monitor of the new one is
		// exactly what is needed.
		//
		// A confirmation this session has yet to re-prove keeps the monitor for
		// the same reason: the record it holds is the only copy, and discarding
		// it on a height the restore itself zeroed would destroy it over an
		// unanswered question.
		let monitor: ChainMonitor;
		if (
			existingMonitor !== undefined &&
			(existingMonitor.isCommitmentConfirmed() ||
				existingMonitor.isCommitmentReverifyPending()) &&
			plan.spliceAdoption === null &&
			plan.v2Adoption === null
		) {
			monitor = existingMonitor;
			monitor.setDestinationScript(destinationScript);
		} else {
			// Signing with the channel's own per-channel keys when present,
			// falling back to node-level base secrets.
			const perCh = this.perChannelMonitorKeys(channel);
			monitor = new ChainMonitor(
				state,
				destinationScript,
				feeRatePerVbyte,
				perCh?.revocationBasepointSecret ||
					this.config.revocationBasepointSecret ||
					this.config.localFundingPrivkey,
				perCh?.paymentBasepointSecret ||
					this.config.paymentBasepointSecret ||
					this.config.localFundingPrivkey,
				network,
				perCh?.delayedPaymentBasepointSecret ||
					this.config.delayedPaymentBasepointSecret ||
					this.config.localFundingPrivkey,
				perCh?.htlcBasepointSecret || this.config.htlcBasepointSecret
			);
		}
		this.monitors.set(idHex, monitor);
		this._seedMonitorPreimages(idHex, monitor);
		// Persist the monitor NOW. Without this it only reaches storage once the
		// funding spend is detected on-chain — if the session ends first, the
		// next restore sees FORCE_CLOSED with no monitor, never re-watches the
		// funding, and the to_local sweep is silently orphaned.
		this.emit('monitor:updated', idHex, monitor);

		return { ok: true, actions };
	}

	/**
	 * Handle when a channel's funding outpoint is spent on-chain.
	 * Creates a ChainMonitor if one doesn't exist, then processes chain actions.
	 */
	handleFundingSpent(
		channelId: Buffer,
		spendingTx: import('bitcoinjs-lib').Transaction,
		blockHeight: number,
		destinationScript: Buffer,
		feeRatePerVbyte = 10,
		revocationBasepointSecret?: Buffer,
		paymentPrivkey?: Buffer,
		network?: import('bitcoinjs-lib').Network,
		// Which funding outpoint the reporting watch saw this transaction
		// spend (issue #479). APPENDED, never inserted: ChannelManager is
		// exported, and moving an existing optional argument breaks a
		// TypeScript consumer's build and silently shifts a JavaScript
		// consumer's key material and network into the wrong slots. The one
		// production caller passing it writes the intervening arguments out,
		// which is the cost of not breaking everyone else's.
		spentOutpoint?: { txid: string; outputIndex: number }
	): ChainAction[] {
		const channelIdHex = channelId.toString('hex');
		let monitor = this.monitors.get(channelIdHex);

		if (!monitor) {
			const channel = this.channels.get(channelIdHex);
			if (!channel) return [];

			const state = channel.getFullState();
			// Prefer explicitly-passed secrets, then the channel's per-channel keys,
			// then node-level base secrets. Per-channel keys are essential here: on a
			// remote force-close our balance sits in the to_remote output, which is
			// locked to this channel's payment basepoint — not the base key.
			const perCh = this.perChannelMonitorKeys(channel);
			monitor = new ChainMonitor(
				state,
				destinationScript,
				feeRatePerVbyte,
				revocationBasepointSecret ||
					perCh?.revocationBasepointSecret ||
					this.config.revocationBasepointSecret ||
					this.config.localFundingPrivkey,
				paymentPrivkey ||
					perCh?.paymentBasepointSecret ||
					this.config.paymentBasepointSecret ||
					this.config.localFundingPrivkey,
				network,
				perCh?.delayedPaymentBasepointSecret ||
					this.config.delayedPaymentBasepointSecret ||
					this.config.localFundingPrivkey,
				perCh?.htlcBasepointSecret || this.config.htlcBasepointSecret
			);
			this.monitors.set(channelIdHex, monitor);
			this._seedMonitorPreimages(channelIdHex, monitor);
		}

		// Captured BEFORE the report so a DEMOTION (a confirmed spend pushed back
		// to the mempool by a reorg, or its clock stopped by a valid competing
		// mempool spend) can be told from an ordinary mempool-first sighting.
		const wasCommitmentConfirmed = monitor.isCommitmentConfirmed();
		const chainActions = monitor.handleFundingSpent(
			spendingTx,
			blockHeight,
			spentOutpoint
		);
		this.processChainActions(channelId, chainActions);

		// Reconcile the channel state machine with the on-chain close so that
		// listChannels() reflects reality after an offline close is detected on
		// restart. The monitor records the classified commitment for us.
		const broadcast = monitor.getFullState().commitmentBroadcast;
		if (broadcast) {
			const channel = this.channels.get(channelIdHex);
			if (channel) {
				const isCoop =
					broadcast.commitmentType === CommitmentType.COOPERATIVE_CLOSE;
				// A peer commitment seen only in the MEMPOOL must not close the
				// channel yet (issue #559): flipping to FORCE_CLOSED here disarms
				// the scanExpiringHtlcs deadline backstop, so a peer parking a
				// below-floor commitment could wait out cltv_expiry with our own
				// CPFP-able commitment never broadcast as a competing spend, while
				// our preimage claim on their tx (CSV-1) stays unreleasable until
				// THEY choose to confirm. The funding watch re-reports the spend
				// with its current height every block, so the flip and its events
				// simply move to confirmation. OUR commitment is exempt
				// (forceClose() already moved the state), and so is a FUTURE
				// commitment: our state is provably stale there, and the backstop
				// broadcasting it would forfeit the balance to the justice path.
				const mempoolOnlyPeerCommitment =
					broadcast.blockHeight <= 0 &&
					(broadcast.commitmentType ===
						CommitmentType.THEIR_CURRENT_COMMITMENT ||
						broadcast.commitmentType ===
							CommitmentType.THEIR_REVOKED_COMMITMENT);
				if (mempoolOnlyPeerCommitment) {
					// Only when the record describes THIS report: a mempool sighting
					// of a competitor to an already-recorded spend keeps the old
					// record (demotion, issue 352) and must not CPFP the newcomer.
					if (broadcast.txid === spendingTx.getId()) {
						this._maybeCpfpTheirCommitment(
							channelId,
							channel.getFullState(),
							spendingTx,
							feeRatePerVbyte
						);
					}
				} else if (channel.markClosedOnChain(!isCoop)) {
					// A non-coop spend of a channel we did not already force-close
					// is the peer's unilateral close (current, future, or revoked
					// commitment). Our own broadcast emits at forceClose() time.
					if (
						!isCoop &&
						broadcast.commitmentType !== CommitmentType.OUR_COMMITMENT
					) {
						this.emit('channel:force-closing', channelId, 'remote');
					}
					this.emit('channel:closed', channelId);
				}
				this._maybeRearmDemotedOurCommitment(
					channelId,
					broadcast,
					wasCommitmentConfirmed,
					monitor.isCommitmentConfirmed(),
					feeRatePerVbyte
				);
			}
		}

		this.emit('monitor:updated', channelIdHex, monitor);
		return chainActions;
	}

	/**
	 * OUR commitment was confirmed and this report demoted it back to
	 * unconfirmed. The per-block re-CPFP entry is memory-only, so a restart
	 * during the confirmed window leaves nothing to resume and the demoted
	 * floor-feerate commitment rides unbumped past cltv_expiry (issue #578).
	 * rearmCommitmentCpfp re-broadcasts the commitment and re-attaches a CPFP
	 * child; it no-ops when a parked entry is already resuming, and carries the
	 * guards that keep us off a peer's (possibly revoked) close.
	 *
	 * Keyed on the classification the report LEFT behind, not the one it found:
	 * a re-report that repairs OUR -> THEIR_CURRENT (issue #573) is not a
	 * demotion of our commitment, and re-broadcasting ours over theirs would
	 * forgo a justice claim.
	 */
	private _maybeRearmDemotedOurCommitment(
		channelId: Buffer,
		broadcast: { commitmentType: CommitmentType; txid: string },
		wasConfirmed: boolean,
		isConfirmed: boolean,
		feeRatePerVbyte: number
	): void {
		if (!wasConfirmed || isConfirmed) return;
		if (broadcast.commitmentType !== CommitmentType.OUR_COMMITMENT) return;
		// A still-parked entry makes rearmCommitmentCpfp a no-op, and only the
		// re-CPFP loop's own confirmed pass sets sawConfirmation. The report that
		// confirms and the one that demotes can both land between two passes (the
		// funding watch fetches history off its own schedule), which would leave
		// the demoted package waiting out the re-bump interval and the feerate
		// gate. Mark it here so the next pass skips both.
		const entry = this._pendingCommitmentCpfp.get(channelId.toString('hex'));
		if (entry && entry.action.commitmentTxid === broadcast.txid) {
			entry.sawConfirmation = true;
		}
		this.rearmCommitmentCpfp(channelId, feeRatePerVbyte);
	}

	/**
	 * The funding watch fetched the funding script's history successfully and
	 * found NO spender: whatever spend this channel's monitor has recorded as
	 * confirmed is no longer in the chain or the mempool (issue 352). Let the
	 * monitor stop its irrevocable-depth clock until positive evidence returns.
	 *
	 * `scan` names the outpoint that evidence is about. The monitor decides
	 * whether its record answers to it, because the record is the durable half
	 * and the watcher's is not (issue #479). Returns whether anything was
	 * actually retracted, so the caller can tell a verdict that landed from one
	 * that was refused.
	 */
	handleFundingSpendAbsent(
		channelId: Buffer,
		scan?: IFundingSpendScan,
		// Live force-close feerate, used only to re-arm OUR commitment's CPFP
		// when the retraction demotes a confirmed close. APPENDED, never
		// inserted, for the same published-API reason as handleFundingSpent.
		feeRatePerVbyte = 10
	): boolean {
		const channelIdHex = channelId.toString('hex');
		const monitor = this.monitors.get(channelIdHex);
		if (!monitor) return false;
		const wasCommitmentConfirmed = monitor.isCommitmentConfirmed();
		if (!monitor.handleFundingSpendAbsent(scan)) return false;
		this.emit('monitor:updated', channelIdHex, monitor);
		// A spend absent from a successfully fetched history is gone from the
		// chain AND the mempool, so an unbumped commitment here is the same
		// fund-loss shape the re-report path guards (issue #578).
		const broadcast = monitor.getFullState().commitmentBroadcast;
		if (broadcast) {
			this._maybeRearmDemotedOurCommitment(
				channelId,
				broadcast,
				wasCommitmentConfirmed,
				monitor.isCommitmentConfirmed(),
				feeRatePerVbyte
			);
		}
		return true;
	}

	/**
	 * Forward new block to all active chain monitors.
	 */
	handleNewBlock(blockHeight: number): ChainAction[] {
		this._currentBlockHeight = blockHeight;
		// Update block height on all channels for CLTV validation
		for (const channel of this.channels.values()) {
			channel.setBlockHeight(blockHeight);
		}

		// Invariant keeper for settles deferred during quiescence (issue 430):
		// terminal quiescence exits and reestablish gaps have no event to drain
		// on, so retry every parked channel each block.
		for (const channelIdHex of [...this.pendingQuiescentSettles.keys()]) {
			this._drainDeferredSettles(channelIdHex);
		}

		const allActions: ChainAction[] = [];

		for (const [channelIdHex, monitor] of this.monitors) {
			if (monitor.isFullyResolved()) continue;

			const actions = monitor.handleNewBlock(blockHeight);
			// Persist the block transition before routing terminal or broadcast
			// actions. A channel:resolved listener can close the channel immediately,
			// so the monitor must already be marked dirty at that boundary.
			this.emit('monitor:updated', channelIdHex, monitor);
			if (actions.length > 0) {
				const channelId = Buffer.from(channelIdHex, 'hex');
				this.processChainActions(channelId, actions);
				allActions.push(...actions);
				// REBUILD_SWEEP is applied while actions are processed and can replace
				// tracked sweep metadata. Persist that post-action state as well.
				this.emit('monitor:updated', channelIdHex, monitor);
			}
		}

		return allActions;
	}

	/**
	 * Handle when a tracked output is spent on-chain.
	 */
	handleOutputSpent(
		txid: string,
		outputIndex: number,
		spendingTx: import('bitcoinjs-lib').Transaction,
		blockHeight: number
	): ChainAction[] {
		// Find which monitor tracks this output
		for (const [channelIdHex, monitor] of this.monitors) {
			const tracked = monitor.getTrackedOutputs();
			const hasOutput = tracked.some(
				(o) => o.txid === txid && o.outputIndex === outputIndex
			);

			if (hasOutput) {
				const actions = monitor.handleOutputSpent(
					txid,
					outputIndex,
					spendingTx,
					blockHeight
				);
				const channelId = Buffer.from(channelIdHex, 'hex');
				this.emit('monitor:updated', channelIdHex, monitor);
				this.processChainActions(channelId, actions);
				if (actions.length > 0) {
					this.emit('monitor:updated', channelIdHex, monitor);
				}
				return actions;
			}
		}

		return [];
	}

	/**
	 * Reorg recovery: a previously-observed spend of a tracked output has been evicted
	 * from the active chain. Route it to the owning monitor so it can re-arm and
	 * re-broadcast our sweep (penalty / HTLC-success / to_local) before the
	 * counterparty's competing timelock matures.
	 */
	handleOutputUnspent(txid: string, outputIndex: number): ChainAction[] {
		for (const [channelIdHex, monitor] of this.monitors) {
			const tracked = monitor.getTrackedOutputs();
			if (
				tracked.some((o) => o.txid === txid && o.outputIndex === outputIndex)
			) {
				const actions = monitor.handleSpendUnconfirmed(txid, outputIndex);
				this.emit('monitor:updated', channelIdHex, monitor);
				if (actions.length > 0) {
					this.processChainActions(Buffer.from(channelIdHex, 'hex'), actions);
					this.emit('monitor:updated', channelIdHex, monitor);
				}
				return actions;
			}
		}
		return [];
	}

	/**
	 * Restore a chain monitor from persisted state.
	 */
	restoreMonitor(channelId: string, monitor: ChainMonitor): void {
		this.monitors.set(channelId, monitor);
		this._harvestMonitorPreimages(monitor);
		this._seedMonitorPreimages(channelId, monitor);
	}

	/**
	 * Recover a preimage that is durable only in a restored monitor's state
	 * (issue 557). handleOutputSpent persists the monitor, whose spend scan
	 * already stored the learned preimage in knownPreimages, and routes the
	 * PREIMAGE_LEARNED action into a separate later commit; a crash between
	 * the two strands the preimage here. The next boot's re-reported spend is
	 * dropped as already recorded and the fresh scan is suppressed by the
	 * knownPreimages dedup, so without this harvest the inbound HTLC of the
	 * forward is never fulfilled and the forwarded amount is lost. The node
	 * re-records every stored preimage into _knownPreimages before monitors
	 * are restored, so an entry missing from it is exactly a stranded one:
	 * re-emitting preimage:learned re-runs the full consumption path (durable
	 * node-store save, monitor seeding, upstream settle now or at the
	 * reestablish tail). The typeof guard tolerates stub monitors.
	 */
	private _harvestMonitorPreimages(monitor: ChainMonitor): void {
		if (typeof monitor.getKnownPreimages !== 'function') return;
		for (const [hashHex, preimage] of monitor.getKnownPreimages()) {
			if (this._knownPreimages.has(hashHex)) continue;
			this._knownPreimages.set(hashHex, preimage);
			this.emit('preimage:learned', Buffer.from(hashHex, 'hex'), preimage);
		}
	}

	/**
	 * Get the chain monitor for a specific channel.
	 */
	/**
	 * Record a learned payment preimage and deliver it to every chain monitor so
	 * a received HTLC can be claimed on-chain after a force-close. Without this
	 * wiring node-held preimages never reach the monitors (ChainMonitor.addPreimage
	 * had no production caller), so an inbound HTLC that must be settled on-chain
	 * — a hold-invoice, or a crash between learning the preimage and fulfilling —
	 * would fall to the counterparty's timeout path: direct loss of the HTLC value.
	 * Preimages are retained so monitors created later (on force-close) are seeded.
	 */
	recordPreimage(paymentHash: Buffer, preimage: Buffer): void {
		this._knownPreimages.set(paymentHash.toString('hex'), preimage);
		for (const [channelIdHex, monitor] of this.monitors) {
			const actions = monitor.addPreimage(paymentHash, preimage);
			// Request persistence of the preimage and any newly built sweep before
			// exposing a broadcast side effect. This also covers an uneconomic claim
			// that emits no transaction but must be retried after a fee change.
			this.emit('monitor:updated', channelIdHex, monitor);
			if (actions.length > 0) {
				this.processChainActions(Buffer.from(channelIdHex, 'hex'), actions);
				this.emit('monitor:updated', channelIdHex, monitor);
			}
		}
	}

	/** Seed a freshly created/restored monitor with all known preimages. */
	private _seedMonitorPreimages(
		channelIdHex: string,
		monitor: ChainMonitor
	): void {
		const channelId = Buffer.from(channelIdHex, 'hex');
		const pendingActions: ChainAction[] = [];
		let seeded = false;
		for (const [hashHex, preimage] of this._knownPreimages) {
			const actions = monitor.addPreimage(
				Buffer.from(hashHex, 'hex'),
				preimage
			);
			seeded = true;
			pendingActions.push(...actions);
		}
		if (!seeded) return;

		// Request a save of every seeded preimage and built claim before routing.
		this.emit('monitor:updated', channelIdHex, monitor);
		if (pendingActions.length > 0) {
			this.processChainActions(channelId, pendingActions);
			this.emit('monitor:updated', channelIdHex, monitor);
		}
	}

	getMonitor(channelId: Buffer): ChainMonitor | undefined {
		return this.monitors.get(channelId.toString('hex'));
	}

	/**
	 * Get all chain monitors, keyed by channel id hex.
	 */
	getMonitors(): Map<string, ChainMonitor> {
		return this.monitors;
	}

	/**
	 * Feed a fresh fee estimate to chain monitors and act on what it unblocks.
	 *
	 * updateFeeRate is not purely a setter: a breach claim declined as uneconomic
	 * at a spiked feerate becomes affordable when the spike passes, and it is
	 * retried right here rather than waiting for the next block. Looping monitors
	 * without routing the returned actions would build those sweeps and never
	 * broadcast them.
	 *
	 * @param feeRatePerKw Fee rate in sat/kw.
	 * @param channelIds Channel id hexes to update; every monitor when omitted.
	 */
	updateMonitorFeeRates(feeRatePerKw: number, channelIds?: string[]): void {
		const targets = channelIds ?? [...this.monitors.keys()];
		for (const channelIdHex of targets) {
			const monitor = this.monitors.get(channelIdHex);
			// Restored/injected monitors are not guaranteed to implement it.
			if (!monitor || typeof monitor.updateFeeRate !== 'function') continue;
			const sweepHexBefore = new Map(
				monitor
					.getTrackedOutputs()
					.map(
						(output) =>
							[
								`${output.txid}:${output.outputIndex}`,
								output.sweepTxHex
							] as const
					)
			);
			const actions = monitor.updateFeeRate(feeRatePerKw) ?? [];
			// A CSV-held sweep stores its template and maturity without emitting an
			// action until it matures. Persist that actionless mutation too.
			const storedSweep = monitor
				.getTrackedOutputs()
				.some(
					(output) =>
						sweepHexBefore.get(`${output.txid}:${output.outputIndex}`) !==
						output.sweepTxHex
				);
			if (actions.length === 0 && !storedSweep) continue;
			// Request a save of newly built sweeps and decline metadata before any
			// broadcast or operator event is routed.
			this.emit('monitor:updated', channelIdHex, monitor);
			if (actions.length > 0) {
				this.processChainActions(Buffer.from(channelIdHex, 'hex'), actions);
				this.emit('monitor:updated', channelIdHex, monitor);
			}
		}
	}

	/**
	 * Mark a closing channel as fully resolved on-chain (all tracked outputs of
	 * the close irrevocably swept/claimed) by transitioning it to CLOSED.
	 *
	 * @returns true if the channel transitioned, false if it was missing or not
	 *   in a closing state (idempotent).
	 */
	markChannelResolved(channelId: Buffer): boolean {
		const channel = this.channels.get(channelId.toString('hex'));
		if (!channel) return false;
		return channel.markResolved();
	}

	/**
	 * Channel-scoped messages that lead with a 32-byte channel_id and are only
	 * ever valid from the peer that owns that lifecycle. Dispatching one from
	 * any other peer must be refused BEFORE it reaches the channel state machine:
	 * several of these can drive the machine to emit a BOLT 1 error (a bad
	 * commitment signature, a reestablish with next_commitment_number 0), which
	 * now force-closes the channel. Resolving the channel globally by id would
	 * let peer X close peer Y's channel with a single forged message.
	 *
	 * The resolver covers permanent channels, direct temporary ids and derived
	 * v2 ids that still live in tempChannels. This protects both interactive v2
	 * opens and the same message family when it is reused for a live splice.
	 *
	 * ERROR/WARNING are excluded, since handleErrorMsg has its own BOLT 1
	 * ownership and all-channels handling. OPEN_CHANNEL and OPEN_CHANNEL2 create
	 * new lifecycles, while ACCEPT_CHANNEL2 has its own exact owner check.
	 */
	private static readonly OWNED_CHANNEL_MESSAGES: ReadonlySet<number> =
		new Set<number>([
			MessageType.ACCEPT_CHANNEL,
			MessageType.FUNDING_CREATED,
			MessageType.FUNDING_SIGNED,
			MessageType.CHANNEL_READY,
			MessageType.UPDATE_ADD_HTLC,
			MessageType.UPDATE_FULFILL_HTLC,
			MessageType.UPDATE_FAIL_HTLC,
			MessageType.UPDATE_FAIL_MALFORMED_HTLC,
			MessageType.COMMITMENT_SIGNED,
			MessageType.REVOKE_AND_ACK,
			MessageType.UPDATE_FEE,
			MessageType.UPDATE_BLOCKHEIGHT,
			MessageType.SHUTDOWN,
			MessageType.CLOSING_SIGNED,
			MessageType.CLOSING_COMPLETE,
			MessageType.CLOSING_SIG,
			MessageType.CHANNEL_REESTABLISH,
			MessageType.STFU,
			MessageType.SPLICE,
			MessageType.SPLICE_ACK,
			MessageType.SPLICE_LOCKED,
			MessageType.START_BATCH,
			MessageType.ANNOUNCEMENT_SIGNATURES,
			// Interactive-tx is shared by temporary v2 opens and permanent
			// splices. The resolver below guards every supported id shape.
			MessageType.TX_ADD_INPUT,
			MessageType.TX_ADD_OUTPUT,
			MessageType.TX_REMOVE_INPUT,
			MessageType.TX_REMOVE_OUTPUT,
			MessageType.TX_COMPLETE,
			MessageType.TX_SIGNATURES,
			MessageType.TX_INIT_RBF,
			MessageType.TX_ACK_RBF,
			MessageType.TX_ABORT
		]);

	/**
	 * Refuse a channel message that names a channel the sending peer does not
	 * own. Resolve the same permanent, derived and temporary id shapes used by
	 * the handlers so an interactive open is protected before promotion too.
	 * Unknown ids fall through to the handler. Returns true when the message
	 * should be dropped.
	 */
	private isForeignChannelMessage(
		peerPubkey: string,
		type: number,
		payload: Buffer
	): boolean {
		if (!ChannelManager.OWNED_CHANNEL_MESSAGES.has(type)) return false;
		if (payload.length < 32) return false;
		const channelId = payload.subarray(0, 32);
		const channel =
			this.findChannelByChannelId(channelId) ||
			this.findChannelByChannelIdInTemp(channelId) ||
			this.findTempChannel(channelId);
		if (!channel) return false;
		const owner = this.findPeerForChannel(channel);
		return owner !== undefined && owner !== peerPubkey;
	}

	/**
	 * Central message dispatch handler.
	 */
	handleMessage(peerPubkey: string, type: number, payload: Buffer): void {
		try {
			if (this.isForeignChannelMessage(peerPubkey, type, payload)) {
				// A peer quoting another peer's channel_id: drop it silently. BOLT 1
				// only requires an error reply for our own closed/unknown channels,
				// and replying here would leak that the channel exists and hand the
				// sender a second way to provoke traffic about it.
				this.emit(
					'error',
					payload.subarray(0, 32),
					`Ignoring ${type} for a channel owned by another peer`
				);
				return;
			}
			switch (type) {
				case MessageType.OPEN_CHANNEL:
					this.handleOpenChannel(peerPubkey, payload);
					break;
				case MessageType.ACCEPT_CHANNEL:
					this.handleAcceptChannel(peerPubkey, payload);
					break;
				case MessageType.FUNDING_CREATED:
					this.handleFundingCreated(peerPubkey, payload);
					break;
				case MessageType.FUNDING_SIGNED:
					this.handleFundingSigned(peerPubkey, payload);
					break;
				case MessageType.CHANNEL_READY:
					this.handleChannelReady(peerPubkey, payload);
					break;
				case MessageType.UPDATE_ADD_HTLC:
					this.handleUpdateAddHtlc(peerPubkey, payload);
					break;
				case MessageType.UPDATE_FULFILL_HTLC:
					this.handleUpdateFulfillHtlc(peerPubkey, payload);
					break;
				case MessageType.UPDATE_FAIL_HTLC:
					this.handleUpdateFailHtlc(peerPubkey, payload);
					break;
				case MessageType.UPDATE_FAIL_MALFORMED_HTLC:
					this.handleUpdateFailMalformedHtlc(peerPubkey, payload);
					break;
				case MessageType.COMMITMENT_SIGNED:
					this.handleCommitmentSigned(peerPubkey, payload);
					break;
				case MessageType.REVOKE_AND_ACK:
					this.handleRevokeAndAck(peerPubkey, payload);
					break;
				case MessageType.UPDATE_FEE:
					this.handleUpdateFeeMsg(peerPubkey, payload);
					break;
				case MessageType.UPDATE_BLOCKHEIGHT:
					this.handleUpdateBlockheightMsg(peerPubkey, payload);
					break;
				case MessageType.SHUTDOWN:
					this.handleShutdownMsg(peerPubkey, payload);
					break;
				case MessageType.CLOSING_SIGNED:
					this.handleClosingSignedMsg(peerPubkey, payload);
					break;
				case MessageType.CLOSING_COMPLETE:
					this.handleClosingCompleteMsg(peerPubkey, payload);
					break;
				case MessageType.CLOSING_SIG:
					this.handleClosingSigMsg(peerPubkey, payload);
					break;
				case MessageType.CHANNEL_REESTABLISH:
					this.handleChannelReestablish(peerPubkey, payload);
					break;
				case MessageType.STFU:
					this.handleStfu(peerPubkey, payload);
					break;
				case MessageType.SPLICE:
					this.handleSpliceMsg(peerPubkey, payload);
					break;
				case MessageType.SPLICE_ACK:
					this.handleSpliceAckMsg(peerPubkey, payload);
					break;
				case MessageType.SPLICE_LOCKED:
					this.handleSpliceLockedMsg(peerPubkey, payload);
					break;
				case MessageType.START_BATCH:
					this.handleStartBatchMsg(peerPubkey, payload);
					break;
				case MessageType.OPEN_CHANNEL2:
					this.handleOpenChannel2(peerPubkey, payload);
					break;
				case MessageType.ACCEPT_CHANNEL2:
					this.handleAcceptChannel2Msg(peerPubkey, payload);
					break;
				case MessageType.TX_ADD_INPUT:
					this.handleTxAddInput(peerPubkey, payload);
					break;
				case MessageType.TX_ADD_OUTPUT:
					this.handleTxAddOutput(peerPubkey, payload);
					break;
				case MessageType.TX_REMOVE_INPUT:
					this.handleTxRemoveInput(peerPubkey, payload);
					break;
				case MessageType.TX_REMOVE_OUTPUT:
					this.handleTxRemoveOutput(peerPubkey, payload);
					break;
				case MessageType.TX_COMPLETE:
					this.handleTxCompleteMsg(peerPubkey, payload);
					break;
				case MessageType.TX_SIGNATURES:
					this.handleTxSignaturesMsg(peerPubkey, payload);
					break;
				case MessageType.TX_INIT_RBF:
					this.handleTxInitRbfMsg(peerPubkey, payload);
					break;
				case MessageType.TX_ACK_RBF:
					this.handleTxAckRbfMsg(peerPubkey, payload);
					break;
				case MessageType.TX_ABORT:
					this.handleTxAbortMsg(peerPubkey, payload);
					break;
				case MessageType.ANNOUNCEMENT_SIGNATURES:
					this.handleAnnouncementSignaturesMsg(peerPubkey, payload);
					break;
				case MessageType.ERROR:
					this.handleErrorMsg(peerPubkey, payload);
					break;
				case MessageType.WARNING:
					this.handleWarningMsg(peerPubkey, payload);
					break;
				default:
					break;
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			this.emit(
				'error',
				null,
				`Error handling message type ${type}: ${message}`
			);
		}
	}

	// ─────────────── Message Handlers ───────────────

	private handleOpenChannel(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeOpenChannelMessage>;
		try {
			msg = decodeOpenChannelMessage(payload);
		} catch (err) {
			const detail = err instanceof Error ? err.message : String(err);
			const reason = `Undecodable open_channel: ${detail}`;
			// No channel exists to fail; refuse the open the way the decoded
			// refusals below do. The temporary_channel_id sits at 32..64,
			// after the chain_hash; below 64 bytes there is no id that means
			// what we would mean by it, so the refusal stays local.
			if (payload.length >= 64) {
				this.refuseInboundOpen(
					peerPubkey,
					Buffer.from(payload.subarray(32, 64)),
					reason
				);
			} else {
				this.emitContained('error', null, reason);
			}
			return;
		}

		// BOLT 1 reserves the all-zero channel_id for "all channels with this
		// peer", so an open under it is unanswerable: every refusal below is
		// scoped to the id the opener chose, and one scoped to THIS id would read
		// as "fail every channel you have with me" rather than "this open is
		// refused". Dropped first, ahead of the chain, namespace and duplicate-id
		// refusals as well as any key derivation, because those refusals are
		// wire-visible too and would each carry the same instruction.
		// refuseInboundOpen suppresses it a second time, for the v2 callers and
		// for anything added later that reaches it another way.
		if (msg.temporaryChannelId.every((b) => b === 0)) {
			this.emitContained(
				'error',
				msg.temporaryChannelId,
				'open_channel refused: temporary_channel_id is the reserved all-zero id'
			);
			return;
		}

		// Reject opens for a chain we do not operate on (same guard as the v2
		// open_channel2 path below).
		if (
			this.config.chainHash &&
			msg.chainHash &&
			!msg.chainHash.equals(this.config.chainHash)
		) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.temporaryChannelId,
				`open_channel for unknown chain ${msg.chainHash.toString('hex')}`
			);
			return;
		}
		if (this._namespaceCannotRecordANewChannel()) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.temporaryChannelId,
				NAMESPACE_LOST_REFUSAL
			);
			return;
		}
		const tempId = msg.temporaryChannelId.toString('hex');
		if (this.channelIdInUse(tempId)) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.temporaryChannelId,
				'open_channel refused: temporary_channel_id is already in use'
			);
			return;
		}
		const chKeys = this.deriveKeysForNewChannel();
		const state = createAcceptorState({
			temporaryChannelId: msg.temporaryChannelId,
			fundingSatoshis: msg.fundingSatoshis,
			pushMsat: msg.pushMsat,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed,
			remoteBasepoints: {
				fundingPubkey: msg.fundingPubkey,
				revocationBasepoint: msg.revocationBasepoint,
				paymentBasepoint: msg.paymentBasepoint,
				delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
				htlcBasepoint: msg.htlcBasepoint,
				firstPerCommitmentPoint: msg.firstPerCommitmentPoint
			},
			remoteConfig: {
				dustLimitSatoshis: msg.dustLimitSatoshis,
				maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
				channelReserveSatoshis: msg.channelReserveSatoshis,
				htlcMinimumMsat: msg.htlcMinimumMsat,
				toSelfDelay: msg.toSelfDelay,
				maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
				feeratePerKw: msg.feeratePerKw
			}
		});

		const signer = this.makeSigner(
			chKeys.channelIndex,
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		channel.channelKeyIndex = chKeys.channelIndex;
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);

		// Record trust-set membership only. Zero-conf semantics (minimum_depth 0,
		// fast-tracked channel_ready) are flipped by handleOpenChannel itself and
		// ONLY when the opener explicitly proposed the zero_conf channel type:
		// membership alone must not change how ordinary opens validate.
		if (this.zeroConfManager.isTrustedPeer(peerPubkey)) {
			channel.getFullState().trustedPeer = true;
		}

		const actions = channel.handleOpenChannel(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleAcceptChannel(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeAcceptChannelMessage>;
		try {
			msg = decodeAcceptChannelMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'accept_channel',
				err
			);
			return;
		}
		const channel = this.tempChannels.get(
			msg.temporaryChannelId.toString('hex')
		);
		if (!channel) {
			this.emit(
				'error',
				null,
				'Unknown temporary_channel_id in accept_channel'
			);
			return;
		}

		const actions = channel.handleAcceptChannel(msg);
		this.processActions(peerPubkey, channel, actions);

		// Only emit channel:accepted if accept was successful (no errors)
		const hasError = actions.some((a) => a.type === ChannelActionType.ERROR);
		if (!hasError) {
			this.emit('channel:accepted', channel, peerPubkey);
		}
	}

	private handleFundingCreated(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeFundingCreatedMessage>;
		try {
			msg = decodeFundingCreatedMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'funding_created',
				err
			);
			return;
		}
		const channel = this.tempChannels.get(
			msg.temporaryChannelId.toString('hex')
		);
		if (!channel) {
			this.emit(
				'error',
				null,
				'Unknown temporary_channel_id in funding_created'
			);
			return;
		}
		const permanentId = deriveChannelId(
			msg.fundingTxid,
			msg.fundingOutputIndex
		);
		if (
			!this.channelIdAvailableForLifecycle(
				permanentId.toString('hex'),
				peerPubkey,
				channel
			)
		) {
			const reason = 'funding_created refused: channel_id is already in use';
			this.processActions(
				peerPubkey,
				channel,
				this.refusalActions(msg.temporaryChannelId, reason)
			);
			return;
		}

		// Set funding outpoint on state before signing (handleFundingCreated also sets these)
		const channelState = channel.getFullState();
		channelState.fundingTxid = msg.fundingTxid;
		channelState.fundingOutputIndex = msg.fundingOutputIndex;

		// Sign the remote's initial commitment transaction with the channel's signer
		const signer = this.signerFor(channel, true);

		let signature = Buffer.alloc(64);
		let partialSignatureWithNonce: Buffer | undefined;
		if (isTaprootChannel(channelState.channelType)) {
			// option_taproot: co-sign the opener's commitment #0 with a MuSig2
			// partial signature instead of ECDSA.
			partialSignatureWithNonce = this.signFundingPartial(
				channelState,
				signer,
				channelState.remoteCurrentPerCommitmentPoint!
			);
		} else {
			signature = signRemoteCommitment(
				channelState,
				signer,
				channelState.remoteCurrentPerCommitmentPoint!
			).signature;
		}

		const actions = channel.handleFundingCreated(
			msg,
			signature,
			partialSignatureWithNonce
		);

		const hasError = actions.some(
			(action) => action.type === ChannelActionType.ERROR
		);
		// Successful funding_created state is persisted under its permanent id.
		// Reserve that id before dispatch, but never promote a rejected open.
		if (!hasError && !this.promoteChannelLifecycle(peerPubkey, channel)) {
			const reason = 'funding_created refused: channel_id is already in use';
			this.processActions(
				peerPubkey,
				channel,
				this.refusalActions(msg.temporaryChannelId, reason)
			);
			return;
		}

		this.processActions(peerPubkey, channel, actions);
	}

	private handleFundingSigned(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeFundingSignedMessage>;
		try {
			msg = decodeFundingSignedMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'funding_signed',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) {
			// Try by scanning temp channels that have a channel ID set
			const ch = this.findChannelByChannelIdInTemp(msg.channelId);
			if (!ch) {
				this.emit(
					'error',
					msg.channelId,
					'Unknown channel_id in funding_signed'
				);
				return;
			}
			const actions = ch.handleFundingSigned(msg);
			const hasError = actions.some(
				(action) => action.type === ChannelActionType.ERROR
			);
			if (!hasError && !this.promoteChannelLifecycle(peerPubkey, ch)) {
				const reason = 'funding_signed refused: channel_id is already in use';
				this.processActions(
					peerPubkey,
					ch,
					this.refusalActions(msg.channelId, reason)
				);
				return;
			}

			this.processActions(peerPubkey, ch, actions);

			// Emit zero-conf ready if applicable
			if (ch.getFullState().zeroConfEnabled) {
				this.emit(
					'channel:zero-conf-ready',
					ch.getChannelId() || msg.channelId
				);
			}

			return;
		}

		const actions = channel.handleFundingSigned(msg);
		this.processActions(peerPubkey, channel, actions);

		// Emit zero-conf ready if applicable
		if (channel.getFullState().zeroConfEnabled) {
			this.emit(
				'channel:zero-conf-ready',
				channel.getChannelId() || msg.channelId
			);
		}
	}

	private handleChannelReady(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeChannelReadyMessage>;
		try {
			msg = decodeChannelReadyMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'channel_ready',
				err
			);
			return;
		}
		// A zero-conf v2 peer sends channel_ready right behind tx_signatures,
		// while the channel still lives in tempChannels (keyed by its derived
		// channelId) — fall back to the temp lookup and promote it.
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId);
		if (!channel) {
			this.emit('error', msg.channelId, 'Unknown channel_id in channel_ready');
			return;
		}

		const actions = channel.handleChannelReady(msg);
		this.processActions(peerPubkey, channel, actions);
		this._promoteV2ChannelIfReady(peerPubkey, channel);
	}

	private handleUpdateAddHtlc(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeUpdateAddHtlcMessage>;
		try {
			msg = decodeUpdateAddHtlcMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_add_htlc',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateAddHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFulfillHtlc(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeUpdateFulfillHtlcMessage>;
		try {
			msg = decodeUpdateFulfillHtlcMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_fulfill_htlc',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFulfillHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFailHtlc(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeUpdateFailHtlcMessage>;
		try {
			msg = decodeUpdateFailHtlcMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_fail_htlc',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFailHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFailMalformedHtlc(
		peerPubkey: string,
		payload: Buffer
	): void {
		let msg: ReturnType<typeof decodeUpdateFailMalformedHtlcMessage>;
		try {
			msg = decodeUpdateFailMalformedHtlcMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_fail_malformed_htlc',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFailMalformedHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleCommitmentSigned(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeCommitmentSignedMessage>;
		try {
			msg = decodeCommitmentSignedMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'commitment_signed',
				err
			);
			return;
		}
		// A v2 open exchanges commitment_signed while the channel still lives in
		// tempChannels (keyed by its now-derived channelId), so fall back to the
		// temp lookup.
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId);
		if (!channel) return;

		const actions = channel.handleCommitmentSigned(msg);
		const hasError = actions.some((a) => a.type === ChannelActionType.ERROR);
		this.processActions(peerPubkey, channel, actions);
		this._promoteV2ChannelIfReady(peerPubkey, channel);

		// BOLT 2: After sending revoke_and_ack, send commitment_signed to commit
		// any pending updates on the remote's side. autoSignAndSendCommitment is a
		// no-op unless we actually owe a commitment (channel.needsCommitment()), so
		// this does not loop. Skip if handleCommitmentSigned returned an error, and
		// skip while a start_batch batch is mid-collection — the reply belongs
		// AFTER the whole batch (one logical update) has been verified and revoked.
		if (!hasError && channel.getChannelId() && !channel.isCollectingBatch()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
	}

	private handleRevokeAndAck(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeRevokeAndAckMessage>;
		try {
			msg = decodeRevokeAndAckMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'revoke_and_ack',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleRevokeAndAck(msg);
		const hadError = actions.some((a) => a.type === ChannelActionType.ERROR);

		// Recovery outbox: the peer's revocation proves it holds every update we
		// sent and the commitment_signed that covered them, so BOLT 2 can never
		// ask us to retransmit them again. This mirrors channel.ts clearing its
		// in-memory _lastSentBatch on the same event, and is what keeps the
		// table bounded to roughly one commitment round per channel.
		//
		// The supersede is STAGED here rather than executed: processActions
		// folds it into the batch's persist request, so the row deletions
		// commit in the SAME transaction as the revoke's channel state. Deleted
		// eagerly, a persist failure (or a crash before the commit) would leave
		// disk holding pre-revoke state whose retransmission bytes are already
		// gone. Staging it before dispatch also keeps the original re-entrancy
		// property: the persist runs at the batch's leading PERSIST_STATE,
		// before any re-entrant dispatch can insert rows for messages the peer
		// has proven nothing about.
		if (!hadError && channel.getChannelId()) {
			this._pendingOutboxSupersede = {
				channelIdHex: channel.getChannelId()!.toString('hex'),
				messageTypes: [...SUPERSEDED_ON_REVOKE_MESSAGE_TYPES]
			};
		}

		this.processActions(peerPubkey, channel, actions);

		// Watchtower: on a clean revocation, hand the just-revoked remote
		// commitment tx (if we cached it) to any listener so it can ship justice
		// data to towers before the peer can broadcast the breach.
		if (!hadError) {
			const revokedTx = channel.takeRevokedCommitmentTx(
				msg.perCommitmentSecret
			);
			const revChannelId = channel.getChannelId();
			if (revokedTx && revChannelId) {
				this.emit(
					'watchtower:backup',
					revChannelId,
					peerPubkey,
					msg.perCommitmentSecret,
					revokedTx
				);
			}
		}

		// BOLT 2: After processing revoke_and_ack, an HTLC_FORWARDED event above may
		// have triggered a local fulfill/fail (setting needsCommitment). Send
		// commitment_signed to commit those updates on the remote's side.
		// autoSignAndSendCommitment is a no-op unless we owe a commitment, so this
		// does not loop.
		const channelId = channel.getChannelId();
		if (channelId) {
			this.autoSignAndSendCommitment(channelId);
		}
	}

	private handleUpdateFeeMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeUpdateFeeMessage>;
		try {
			msg = decodeUpdateFeeMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_fee',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFee(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateBlockheightMsg(
		peerPubkey: string,
		payload: Buffer
	): void {
		let msg: ReturnType<typeof decodeUpdateBlockheightMessage>;
		try {
			msg = decodeUpdateBlockheightMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'update_blockheight',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateBlockheight(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * A payload that failed to DECODE (wrong-length TLV, truncated record, a
	 * lying count) never reaches the handler whose content checks would
	 * wire-fail it; without this, the codec throw died in handleMessage's
	 * catch as a null-id local error. Every guarded message leads with a
	 * 32-byte id at offset 0: funding_created the temporary_channel_id;
	 * shutdown, closing_signed, funding_signed and commitment_signed the
	 * channel_id, which for a v2 open may still be temp-resident. So the
	 * channel can be identified and failed with a properly scoped wire
	 * error. The lookup chain mirrors isForeignChannelMessage, and the owner
	 * check is repeated here rather than relied on from the pre-screen:
	 * accept_channel2 is not in OWNED_CHANNEL_MESSAGES (its handler does its
	 * own owner check, which an undecodable payload never reaches), so a
	 * third party quoting someone else's id in garbage must be refused HERE
	 * or it could fail the victim's channel (issue 426).
	 */
	private failChannelForUndecodablePayload(
		peerPubkey: string,
		payload: Buffer,
		name: string,
		err: unknown
	): void {
		const detail = err instanceof Error ? err.message : String(err);
		const channelId =
			payload.length >= 32 ? Buffer.from(payload.subarray(0, 32)) : null;
		const channel = channelId
			? this.findChannelByChannelId(channelId) ||
			  this.findChannelByChannelIdInTemp(channelId) ||
			  this.findTempChannel(channelId)
			: null;
		if (!channel) {
			this.emit('error', channelId, `Undecodable ${name}: ${detail}`);
			return;
		}
		const owner = this.findPeerForChannel(channel);
		if (owner !== undefined && owner !== peerPubkey) {
			this.emit(
				'error',
				channelId,
				`Ignoring undecodable ${name} for a channel owned by another peer`
			);
			return;
		}
		this.processActions(
			peerPubkey,
			channel,
			channel.failFromMalformedPeerMessage(`Undecodable ${name}: ${detail}`)
		);
	}

	private handleShutdownMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeShutdownMessage>;
		try {
			msg = decodeShutdownMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'shutdown',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		// Stamp the negotiation path BEFORE processing (handleShutdown's script
		// validation and re-send rules depend on it).
		channel.setSimpleClose(this.peerNegotiatedSimpleClose(peerPubkey));

		// Derive default P2WPKH shutdown script from local funding pubkey
		const defaultScript = this.getDefaultShutdownScript();
		// A shutdown for a channel not already closing means the PEER initiated
		// the coop close (a reply to OUR shutdown arrives in SHUTTING_DOWN).
		const wasClosing =
			channel.getState() === ChannelState.SHUTTING_DOWN ||
			channel.getState() === ChannelState.NEGOTIATING_CLOSING;
		const actions = channel.handleShutdown(msg, defaultScript);
		this.processActions(peerPubkey, channel, actions);
		if (
			!wasClosing &&
			(channel.getState() === ChannelState.SHUTTING_DOWN ||
				channel.getState() === ChannelState.NEGOTIATING_CLOSING ||
				channel.getState() === ChannelState.CLOSED)
		) {
			this.emit('channel:pending-close', msg.channelId, 'remote');
		}

		if (channel.getState() !== ChannelState.NEGOTIATING_CLOSING) return;

		if (channel.isSimpleClose()) {
			// option_simple_close: BOTH sides SHOULD send closing_complete.
			this.startSimpleClose(peerPubkey, channel);
			return;
		}

		// BOLT 2: opener must send first closing_signed after both shutdowns exchanged
		if (channel.getRole() === ChannelRole.OPENER) {
			this.applyClosingFeerate(channel);
			const closingActions = channel.proposeClosingFee((feeSatoshis: bigint) =>
				this.signClosingTx(channel, feeSatoshis)
			);
			this.processActions(peerPubkey, channel, closingActions);
		}
	}

	private getDefaultShutdownScript(): Buffer {
		// Prefer the wallet-owned destination (same script force-close sweeps use)
		// so cooperative-close payouts land at a regular wallet address rather than
		// at P2WPKH(funding_pubkey) — which reuses the funding key and previously
		// left funds stranded at an address the wallet doesn't watch. Only use it
		// if it is a valid standard shutdown script.
		if (
			this._walletDestinationScript &&
			isValidShutdownScript(this._walletDestinationScript, true)
		) {
			return this._walletDestinationScript;
		}
		const pubkey = this.config.localBasepoints.fundingPubkey;
		// Fallback (no wallet script configured): P2WPKH output script OP_0 <20-byte-hash>
		return bitcoin.payments.p2wpkh({ pubkey }).output!;
	}

	private handleClosingSignedMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeClosingSignedMessage>;
		try {
			msg = decodeClosingSignedMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'closing_signed',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		// Responder side: the acceptable-fee range is initialized lazily on the
		// first closing_signed, so the live feerate must be in place first.
		this.applyClosingFeerate(channel);
		const actions = channel.handleClosingSigned(
			msg,
			(feeSatoshis: bigint) => this.signClosingTx(channel, feeSatoshis),
			// Gate the CLOSED transition on a valid peer signature over the agreed tx,
			// so a bad-sig fee-echo cannot close the channel + tear down the funding
			// watch (which would leave a later revoked broadcast unpunished).
			(feeSatoshis: bigint, signature: Buffer) =>
				this.verifyPeerClosingSig(channel, feeSatoshis, signature)
		);

		// On agreement, verify the peer's closing signature and broadcast the
		// mutual-close ourselves rather than trusting the peer to do it (BOLT 2).
		const agreed = actions.some(
			(a) => a.type === ChannelActionType.CHANNEL_CLOSED
		);
		if (agreed) {
			// Taproot channels carry the peer's MuSig2 partial in TLV 6; the fixed
			// ECDSA field is zeroed. agreed=true implies the channel already
			// validated the right one is present.
			const theirSig = isTaprootChannel(channel.getFullState().channelType)
				? msg.partialSignature!
				: msg.signature;
			const closeTx = this.buildSignedMutualCloseTx(
				channel,
				msg.feeSatoshis,
				theirSig
			);
			if (closeTx) {
				// Persist the signed close tx BEFORE processActions emits channel:closed
				// (which triggers persistChannel upstream) so a restart in the
				// pre-confirmation window can rebroadcast it and keep the funding watch.
				channel.recordCooperativeCloseTx(Buffer.from(closeTx).toString('hex'));
				this.emit('broadcast:tx', closeTx);
				this.processActions(peerPubkey, channel, actions);
			} else {
				// Defense in depth: handleClosingSigned already gated CLOSED on a valid
				// sig, so we should not reach here — but if the close tx can't be built,
				// do NOT process CHANNEL_CLOSED (keep the channel + funding watch alive).
				// The channel committed CLOSED internally before the build ran, so a
				// bare filter would strand it falsely CLOSED with nothing broadcast:
				// no rebroadcast, no force-close route, and a restart would persist
				// the lie. Roll it back to NEGOTIATING_CLOSING and persist THAT, so
				// every recovery path (retry, reconnect with fresh session, operator
				// force close) stays open.
				channel.getFullState().state = ChannelState.NEGOTIATING_CLOSING;
				this.emit(
					'error',
					msg.channelId,
					'Coop-close: peer closing signature failed to verify'
				);
				this.processActions(peerPubkey, channel, [
					{ type: ChannelActionType.PERSIST_STATE },
					...actions.filter((a) => a.type !== ChannelActionType.CHANNEL_CLOSED)
				]);
			}
		} else {
			this.processActions(peerPubkey, channel, actions);
		}
	}

	/**
	 * Verify a peer's cooperative-close signature over the closing tx built at the
	 * given fee (same tx we would broadcast). Used to gate the CLOSED transition so a
	 * bad-sig fee-echo cannot force close + funding-watch teardown.
	 */
	private verifyPeerClosingSig(
		channel: Channel,
		feeSatoshis: bigint,
		theirSig: Buffer
	): boolean {
		try {
			if (isTaprootChannel(channel.getFullState().channelType)) {
				const cache = this.getOrCreateTaprootClosingSession(
					channel,
					feeSatoshis
				);
				if (!cache) return false;
				const remoteNonce = channel.getClosingNonces().remote;
				if (!remoteNonce) return false;
				return verifyPartialCommitmentSig(
					cache.session as SessionKey,
					theirSig,
					channel.getFullState().remoteBasepoints!.fundingPubkey,
					remoteNonce
				);
			}
			return (
				this.buildVerifiedLegacyCloseTx(channel, feeSatoshis, theirSig) !== null
			);
		} catch {
			return false;
		}
	}

	/**
	 * Build the legacy (non-taproot) closing tx VARIANT the peer's signature
	 * actually covers, or null if it covers neither. BOLT 2 permits the signer
	 * to eliminate its OWN output from the closing transaction, so a valid
	 * signature may be over the canonical two-output tx or over the tx with
	 * the peer's output removed (its value donated to fees); a verifier pinned
	 * to the canonical variant falsely rejects the second, and this PR made
	 * that rejection fatal. Our own output is present in both variants.
	 */
	private buildVerifiedLegacyCloseTx(
		channel: Channel,
		feeSatoshis: bigint,
		theirSig: Buffer
	): {
		tx: import('bitcoinjs-lib').Transaction;
		witnessScript: Buffer;
		fundingSatoshis: bigint;
		localFundingPubkey: Buffer;
		remoteFundingPubkey: Buffer;
	} | null {
		const signer = this.signerFor(channel, false);
		const covers = (
			built: ReturnType<ChannelManager['buildClosingTxAndScript']>
		): boolean =>
			signer.verifyCommitmentSig(
				built.tx,
				theirSig,
				built.remoteFundingPubkey,
				built.witnessScript,
				Number(built.fundingSatoshis)
			);
		const canonical = this.buildClosingTxAndScript(channel, feeSatoshis);
		if (covers(canonical)) return canonical;
		// The eliminated variant only differs when the remote output survived
		// the dust filter in the canonical build.
		if (canonical.tx.outs.length < 2) return null;
		const eliminated = this.buildClosingTxAndScript(channel, feeSatoshis, true);
		return covers(eliminated) ? eliminated : null;
	}

	private buildClosingTxAndScript(
		channel: Channel,
		feeSatoshis: bigint,
		omitRemoteOutput = false
	): {
		tx: import('bitcoinjs-lib').Transaction;
		witnessScript: Buffer;
		fundingSatoshis: bigint;
		localFundingPubkey: Buffer;
		remoteFundingPubkey: Buffer;
	} {
		const { buildClosingTx } = require('../chain/closing');
		const { createFundingScript } = require('../script/funding');

		const state = channel.getFullState();
		const localBalanceSat = state.localBalanceMsat / 1000n;
		const remoteBalanceSat = state.remoteBalanceMsat / 1000n;

		// Fee deducted from opener's balance
		const localIsOpener = state.role === ChannelRole.OPENER;
		const localAmount = localIsOpener
			? localBalanceSat - feeSatoshis
			: localBalanceSat;
		// BOLT 2 lets the signer eliminate its OWN output (value to fees);
		// forcing the amount to zero drops it through the dust filter below.
		const remoteAmount = omitRemoteOutput
			? 0n
			: localIsOpener
			? remoteBalanceSat
			: remoteBalanceSat - feeSatoshis;

		const { tx } = buildClosingTx({
			fundingTxid: state.fundingTxid!.toString('hex'),
			fundingOutputIndex: state.fundingOutputIndex!,
			fundingAmount: state.fundingSatoshis,
			localScriptPubkey: state.localShutdownScript!,
			remoteScriptPubkey: state.remoteShutdownScript!,
			localAmount,
			remoteAmount,
			feeAmount: feeSatoshis,
			// LND builds the taproot coop-close tx RBF-signalled; the sequence
			// is part of the MuSig2 sighash, so it must match exactly.
			sequence: isTaprootChannel(state.channelType) ? 0xfffffffd : 0xffffffff
		});

		const { witnessScript } = createFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints!.fundingPubkey
		);

		return {
			tx,
			witnessScript,
			fundingSatoshis: state.fundingSatoshis,
			localFundingPubkey: state.localBasepoints.fundingPubkey,
			remoteFundingPubkey: state.remoteBasepoints!.fundingPubkey
		};
	}

	private signClosingTx(channel: Channel, feeSatoshis: bigint): Buffer {
		if (isTaprootChannel(channel.getFullState().channelType)) {
			return this.signTaprootClosingPartial(channel, feeSatoshis);
		}
		const { tx, witnessScript, fundingSatoshis } = this.buildClosingTxAndScript(
			channel,
			feeSatoshis
		);
		const signer = this.signerFor(channel, false);
		return signer.signClosingTx(tx, witnessScript, Number(fundingSatoshis));
	}

	// ─────────────── taproot cooperative close (MuSig2) ───────────────

	/**
	 * Get (or build) the MuSig2 signing session for the taproot closing tx at
	 * the given fee. The cache lives on the channel, which clears it whenever
	 * the closing nonces refresh (shutdown (re)transmission). Returns null when
	 * the nonce exchange hasn't completed — the caller treats that as
	 * "cannot sign/verify yet", never as a fallback to ECDSA.
	 *
	 * NONCE SAFETY: one closing session ever signs ONE sighash. If we already
	 * produced a partial in this session, a request at a DIFFERENT fee is
	 * refused (returns null) — a second sighash under the same nonce would leak
	 * the funding key.
	 */
	private getOrCreateTaprootClosingSession(
		channel: Channel,
		feeSatoshis: bigint
	): ITaprootClosingCache | null {
		const cached = channel.getTaprootClosingCache();
		if (cached && cached.feeSatoshis === feeSatoshis) return cached;
		if (cached && cached.ourPartialSig) return null;

		const nonces = channel.getClosingNonces();
		if (!nonces.local || !nonces.remote) return null;

		const state = channel.getFullState();
		if (!state.remoteBasepoints) return null;
		const { tx, fundingSatoshis } = this.buildClosingTxAndScript(
			channel,
			feeSatoshis
		);
		const { p2trOutput } = createTaprootFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints.fundingPubkey
		);
		const sighash = taprootCommitmentSighash(
			tx,
			p2trOutput,
			Number(fundingSatoshis)
		);
		const session = startCommitmentSigningSession(
			sighash,
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints.fundingPubkey,
			nonces.local,
			nonces.remote
		);
		const cache: ITaprootClosingCache = {
			feeSatoshis,
			session,
			tx,
			ourPartialSig: null
		};
		channel.setTaprootClosingCache(cache);
		return cache;
	}

	/**
	 * Produce our 32-byte MuSig2 partial over the closing tx at the given fee.
	 * Idempotent per closing session: the partial is cached and the secret
	 * nonce is consumed exactly once (the musig library purges it after one
	 * partialSign, and the channel's sign-once latch prevents re-entry).
	 */
	private signTaprootClosingPartial(
		channel: Channel,
		feeSatoshis: bigint
	): Buffer {
		const cache = this.getOrCreateTaprootClosingSession(channel, feeSatoshis);
		if (!cache) {
			throw new Error(
				'Taproot closing session unavailable (nonce exchange incomplete or nonce already used at another fee)'
			);
		}
		if (cache.ourPartialSig) return cache.ourPartialSig;
		const nonces = channel.getClosingNonces();
		const signer = this.signerFor(channel, false);
		const partial = signer.signCommitmentPartial(
			cache.session as SessionKey,
			nonces.local!
		);
		cache.ourPartialSig = partial;
		return partial;
	}

	/**
	 * Build the fully-signed mutual-close transaction at the agreed fee, AFTER
	 * verifying the counterparty's closing signature. Returns the serialized tx
	 * to broadcast, or null if their signature does not verify. Previously the
	 * coop-close path reached agreement on fee alone, marked the channel CLOSED,
	 * and relied entirely on the peer to broadcast a valid close — a peer that
	 * echoed the fee with a garbage signature (or never broadcast) left funds in
	 * limbo. We now validate their signature and broadcast the close ourselves.
	 */
	private buildSignedMutualCloseTx(
		channel: Channel,
		feeSatoshis: bigint,
		theirSig: Buffer
	): Buffer | null {
		// Whole-body guard like buildSignedSimpleMutualCloseTx: the taproot
		// path verifies a peer-supplied MuSig2 partial, and garbage bytes make
		// the musig library throw rather than return false (issue 415). A null
		// keeps the channel + funding watch alive at the caller.
		try {
			if (isTaprootChannel(channel.getFullState().channelType)) {
				return this.buildSignedTaprootMutualCloseTx(
					channel,
					feeSatoshis,
					theirSig
				);
			}
			// Sign and broadcast the VARIANT the peer's signature covers (the
			// canonical tx or the one with the peer's own output eliminated);
			// signing the canonical tx against an eliminated-variant signature
			// would assemble an unbroadcastable witness.
			const built = this.buildVerifiedLegacyCloseTx(
				channel,
				feeSatoshis,
				theirSig
			);
			if (!built) {
				return null;
			}
			const signer = this.signerFor(channel, false);
			const ourSig = signer.signClosingTx(
				built.tx,
				built.witnessScript,
				Number(built.fundingSatoshis)
			);
			built.tx.setWitness(
				0,
				ChannelSigner.buildFundingWitness(
					ourSig,
					theirSig,
					built.localFundingPubkey,
					built.remoteFundingPubkey,
					built.witnessScript
				)
			);
			return built.tx.toBuffer();
		} catch {
			return null;
		}
	}

	/**
	 * Taproot mutual close: aggregate our cached partial with the peer's into
	 * the final 64-byte key-spend witness. NEVER signs here — our partial must
	 * already exist in the session cache (made once via signClosingTx); a
	 * missing partial is an internal-ordering error and returns null (the
	 * caller keeps the channel + funding watch alive). Belt-and-braces: the
	 * aggregated signature is verified against the funding output key before
	 * the tx is released for broadcast (mirrors the force-close aggregation
	 * pattern).
	 */
	private buildSignedTaprootMutualCloseTx(
		channel: Channel,
		feeSatoshis: bigint,
		theirPartialSig: Buffer
	): Buffer | null {
		const cache = channel.getTaprootClosingCache();
		if (!cache || cache.feeSatoshis !== feeSatoshis || !cache.ourPartialSig) {
			return null;
		}
		const state = channel.getFullState();
		if (!state.remoteBasepoints) return null;
		const remoteNonce = channel.getClosingNonces().remote;
		if (!remoteNonce) return null;

		// Defense in depth: re-verify the peer's partial against the session
		// even though handleClosingSigned already gated CLOSED on it.
		if (
			!verifyPartialCommitmentSig(
				cache.session as SessionKey,
				theirPartialSig,
				state.remoteBasepoints.fundingPubkey,
				remoteNonce
			)
		) {
			return null;
		}

		const finalSig = aggregateCommitmentSig(
			cache.session as SessionKey,
			cache.ourPartialSig,
			theirPartialSig
		);

		const { p2trOutput, outputKey } = createTaprootFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints.fundingPubkey
		);
		const sighash = taprootCommitmentSighash(
			cache.tx,
			p2trOutput,
			Number(state.fundingSatoshis)
		);
		if (!ecc.verifySchnorr(sighash, outputKey, finalSig)) {
			return null;
		}

		cache.tx.setWitness(0, buildTaprootKeySpendWitness(finalSig));
		return cache.tx.toBuffer();
	}

	// ─────────────── option_simple_close ───────────────

	/**
	 * Kick off (or restart) the simple-close signing flow: send our
	 * closing_complete as closer. Both sides do this independently; each
	 * side's fee comes out of its own output. Skipped when our balance can't
	 * cover a relayable fee — we then simply act as closee for the peer's
	 * closing_complete.
	 */
	/**
	 * Inject the live closing feerate (when a provider is configured) so the
	 * closing fee is priced for the CURRENT chain, not the channel's
	 * commitment feerate (pinned to the 253 sat/kw floor on anchors).
	 */
	private applyClosingFeerate(channel: Channel): void {
		const rate = this.config.getClosingFeeratePerKw?.();
		if (rate !== undefined && rate > 0) {
			channel.setClosingFeeratePerKw(rate);
		}
	}

	private startSimpleClose(peerPubkey: string, channel: Channel): void {
		const { estimateSimpleCloseFee } = require('../chain/closing');
		this.applyClosingFeerate(channel);
		const state = channel.getFullState();
		const localScript = state.localShutdownScript;
		const remoteScript = state.remoteShutdownScript;
		if (!localScript || localScript.length === 0 || !remoteScript) return;

		const feeratePerKw = channel.getClosingFeeratePerKw();
		const fee: bigint = estimateSimpleCloseFee(
			feeratePerKw,
			localScript.length,
			remoteScript.length
		);
		const localSat = state.localBalanceMsat / 1000n;
		if (localSat < fee) {
			// Nothing (or not enough) at stake on our side to pay for a close tx;
			// wait for the peer's closing_complete instead.
			return;
		}

		const actions = channel.sendClosingComplete(
			fee,
			0,
			(variant, feeSatoshis, locktime, closerScript, closeeScript) =>
				this.signSimpleClosingTx(
					channel,
					variant,
					feeSatoshis,
					locktime,
					true,
					closerScript,
					closeeScript
				)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * Build the simple-close tx + funding witness data for one signature
	 * variant. Unlike the legacy builder (opener pays), the CLOSER pays the
	 * whole fee — closerIsLocal maps our/their balances onto closer/closee.
	 */
	private buildSimpleClosingTxAndScript(
		channel: Channel,
		variant: ClosingSigVariant,
		feeSatoshis: bigint,
		locktime: number,
		closerIsLocal: boolean,
		closerScript: Buffer,
		closeeScript: Buffer
	): {
		tx: import('bitcoinjs-lib').Transaction;
		witnessScript: Buffer;
		fundingSatoshis: bigint;
		localFundingPubkey: Buffer;
		remoteFundingPubkey: Buffer;
	} {
		const { buildSimpleClosingTx } = require('../chain/closing');
		const { createFundingScript } = require('../script/funding');

		const state = channel.getFullState();
		const localBalanceSat = state.localBalanceMsat / 1000n;
		const remoteBalanceSat = state.remoteBalanceMsat / 1000n;

		const { tx } = buildSimpleClosingTx({
			fundingTxid: state.fundingTxid!.toString('hex'),
			fundingOutputIndex: state.fundingOutputIndex!,
			closerScriptPubkey: closerScript,
			closeeScriptPubkey: closeeScript,
			closerAmount: closerIsLocal ? localBalanceSat : remoteBalanceSat,
			closeeAmount: closerIsLocal ? remoteBalanceSat : localBalanceSat,
			feeSatoshis,
			locktime,
			variant: variant as number
		});

		const { witnessScript } = createFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints!.fundingPubkey
		);

		return {
			tx,
			witnessScript,
			fundingSatoshis: state.fundingSatoshis,
			localFundingPubkey: state.localBasepoints.fundingPubkey,
			remoteFundingPubkey: state.remoteBasepoints!.fundingPubkey
		};
	}

	private signSimpleClosingTx(
		channel: Channel,
		variant: ClosingSigVariant,
		feeSatoshis: bigint,
		locktime: number,
		closerIsLocal: boolean,
		closerScript: Buffer,
		closeeScript: Buffer
	): Buffer {
		const { tx, witnessScript, fundingSatoshis } =
			this.buildSimpleClosingTxAndScript(
				channel,
				variant,
				feeSatoshis,
				locktime,
				closerIsLocal,
				closerScript,
				closeeScript
			);
		const signer = this.signerFor(channel, false);
		return signer.signClosingTx(tx, witnessScript, Number(fundingSatoshis));
	}

	/**
	 * Verify the peer's signature over the simple-close tx we would broadcast.
	 * Gates every CLOSED transition in the simple-close flow (same posture as
	 * verifyPeerClosingSig on the legacy path).
	 */
	private verifyPeerSimpleClosingSig(
		channel: Channel,
		variant: ClosingSigVariant,
		feeSatoshis: bigint,
		locktime: number,
		closerIsLocal: boolean,
		closerScript: Buffer,
		closeeScript: Buffer,
		theirSig: Buffer
	): boolean {
		try {
			const { tx, witnessScript, fundingSatoshis, remoteFundingPubkey } =
				this.buildSimpleClosingTxAndScript(
					channel,
					variant,
					feeSatoshis,
					locktime,
					closerIsLocal,
					closerScript,
					closeeScript
				);
			const signer = this.signerFor(channel, false);
			return signer.verifyCommitmentSig(
				tx,
				theirSig,
				remoteFundingPubkey,
				witnessScript,
				Number(fundingSatoshis)
			);
		} catch {
			return false;
		}
	}

	/**
	 * Build the fully-signed simple-close tx (after re-verifying the peer's
	 * signature) for broadcast. Returns null if their signature does not verify
	 * — defense in depth behind the state machine's own verify gate, mirroring
	 * buildSignedMutualCloseTx on the legacy path.
	 */
	private buildSignedSimpleMutualCloseTx(
		channel: Channel,
		variant: ClosingSigVariant,
		feeSatoshis: bigint,
		locktime: number,
		closerIsLocal: boolean,
		closerScript: Buffer,
		closeeScript: Buffer,
		theirSig: Buffer
	): Buffer | null {
		try {
			const {
				tx,
				witnessScript,
				fundingSatoshis,
				localFundingPubkey,
				remoteFundingPubkey
			} = this.buildSimpleClosingTxAndScript(
				channel,
				variant,
				feeSatoshis,
				locktime,
				closerIsLocal,
				closerScript,
				closeeScript
			);
			const signer = this.signerFor(channel, false);
			const ourSig = signer.signClosingTx(
				tx,
				witnessScript,
				Number(fundingSatoshis)
			);
			if (
				!signer.verifyCommitmentSig(
					tx,
					theirSig,
					remoteFundingPubkey,
					witnessScript,
					Number(fundingSatoshis)
				)
			) {
				return null;
			}
			tx.setWitness(
				0,
				ChannelSigner.buildFundingWitness(
					ourSig,
					theirSig,
					localFundingPubkey,
					remoteFundingPubkey,
					witnessScript
				)
			);
			return tx.toBuffer();
		} catch {
			return null;
		}
	}

	/** Extract the single (variant, sig) pair from a simple-close message. */
	private static singleClosingSig(
		msg: IClosingCompleteMessage
	): { variant: ClosingSigVariant; sig: Buffer } | null {
		const sigs: Array<{ variant: ClosingSigVariant; sig: Buffer }> = [];
		if (msg.closerOutputOnlySig) {
			sigs.push({
				variant: ClosingSigVariant.CLOSER_OUTPUT_ONLY,
				sig: msg.closerOutputOnlySig
			});
		}
		if (msg.closeeOutputOnlySig) {
			sigs.push({
				variant: ClosingSigVariant.CLOSEE_OUTPUT_ONLY,
				sig: msg.closeeOutputOnlySig
			});
		}
		if (msg.closerAndCloseeSig) {
			sigs.push({
				variant: ClosingSigVariant.CLOSER_AND_CLOSEE,
				sig: msg.closerAndCloseeSig
			});
		}
		return sigs.length === 1 ? sigs[0] : null;
	}

	/**
	 * closing_complete from the peer: we are the CLOSEE. On success the channel
	 * emits closing_sig + CHANNEL_CLOSED; we then broadcast the peer's close tx
	 * ourselves (never trusting the peer to broadcast), with the same
	 * defense-in-depth CHANNEL_CLOSED strip as the legacy path.
	 */
	private handleClosingCompleteMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeClosingCompleteMessage>;
		try {
			msg = decodeClosingCompleteMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'closing_complete',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleClosingComplete(
			msg,
			(variant, feeSatoshis, locktime, closerScript, closeeScript, sig) =>
				this.verifyPeerSimpleClosingSig(
					channel,
					variant,
					feeSatoshis,
					locktime,
					false,
					closerScript,
					closeeScript,
					sig
				),
			(variant, feeSatoshis, locktime, closerScript, closeeScript) =>
				this.signSimpleClosingTx(
					channel,
					variant,
					feeSatoshis,
					locktime,
					false,
					closerScript,
					closeeScript
				)
		);

		// Success is signalled by the closing_sig reply (present even in the
		// concurrent-close race where the channel is already CLOSED and no
		// CHANNEL_CLOSED action is re-emitted). Recover the signed variant from it.
		const replyAction = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as { messageType: MessageType }).messageType ===
					MessageType.CLOSING_SIG
		) as { payload: Buffer } | undefined;
		if (!replyAction) {
			this.processActions(peerPubkey, channel, actions);
			return;
		}
		const reply = replyAction
			? decodeClosingSigMessage(replyAction.payload)
			: null;
		const chosen = reply ? ChannelManager.singleClosingSig(reply) : null;
		const theirSig = chosen
			? {
					[ClosingSigVariant.CLOSER_OUTPUT_ONLY]: msg.closerOutputOnlySig,
					[ClosingSigVariant.CLOSEE_OUTPUT_ONLY]: msg.closeeOutputOnlySig,
					[ClosingSigVariant.CLOSER_AND_CLOSEE]: msg.closerAndCloseeSig
			  }[chosen.variant]
			: undefined;

		const closeTx =
			chosen && theirSig
				? this.buildSignedSimpleMutualCloseTx(
						channel,
						chosen.variant,
						msg.feeSatoshis,
						msg.locktime,
						false,
						msg.closerScriptPubkey,
						msg.closeeScriptPubkey,
						theirSig
				  )
				: null;
		if (closeTx) {
			channel.recordCooperativeCloseTx(Buffer.from(closeTx).toString('hex'));
			this.emit('broadcast:tx', closeTx);
			this.processActions(peerPubkey, channel, actions);
		} else {
			// Defense in depth: the state machine verified the sig already, so we
			// should not get here — but never process CHANNEL_CLOSED (funding-watch
			// teardown) without a broadcastable, verified close tx.
			this.emit(
				'error',
				msg.channelId,
				'Simple close: failed to build verified closing tx'
			);
			this.processActions(
				peerPubkey,
				channel,
				actions.filter((a) => a.type !== ChannelActionType.CHANNEL_CLOSED)
			);
		}
	}

	/**
	 * closing_sig from the peer: we are the CLOSER; broadcast our close tx.
	 */
	private handleClosingSigMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeClosingSigMessage>;
		try {
			msg = decodeClosingSigMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'closing_sig',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleClosingSig(
			msg,
			(variant, feeSatoshis, locktime, closerScript, closeeScript, sig) =>
				this.verifyPeerSimpleClosingSig(
					channel,
					variant,
					feeSatoshis,
					locktime,
					true,
					closerScript,
					closeeScript,
					sig
				)
		);

		// Success = no ERROR action (the concurrent-close race succeeds with an
		// empty action list: already CLOSED, but our alternative tx broadcasts).
		const failed = actions.some((a) => a.type === ChannelActionType.ERROR);
		if (failed) {
			this.processActions(peerPubkey, channel, actions);
			return;
		}

		const chosen = ChannelManager.singleClosingSig(msg);
		const closeTx = chosen
			? this.buildSignedSimpleMutualCloseTx(
					channel,
					chosen.variant,
					msg.feeSatoshis,
					msg.locktime,
					true,
					msg.closerScriptPubkey,
					msg.closeeScriptPubkey,
					chosen.sig
			  )
			: null;
		if (closeTx) {
			channel.recordCooperativeCloseTx(Buffer.from(closeTx).toString('hex'));
			this.emit('broadcast:tx', closeTx);
			this.processActions(peerPubkey, channel, actions);
		} else {
			this.emit(
				'error',
				msg.channelId,
				'Simple close: failed to build verified closing tx'
			);
			this.processActions(
				peerPubkey,
				channel,
				actions.filter((a) => a.type !== ChannelActionType.CHANNEL_CLOSED)
			);
		}
	}

	/**
	 * RBF entry: bump our simple-close fee (option_simple_close only). Callable
	 * once the previous closing_complete round was answered.
	 */
	bumpCloseFee(channelId: Buffer, feeSatoshis: bigint): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.bumpClosingFee(
			feeSatoshis,
			0,
			(variant, fee, locktime, closerScript, closeeScript) =>
				this.signSimpleClosingTx(
					channel,
					variant,
					fee,
					locktime,
					true,
					closerScript,
					closeeScript
				)
		);
		this.processActions(peerPubkey, channel, actions);
		const errorAction = actions.find((a) => a.type === ChannelActionType.ERROR);
		if (errorAction) {
			return {
				ok: false,
				actions,
				error: (errorAction as { message: string }).message
			};
		}
		return { ok: true, actions };
	}

	/**
	 * Propose initial closing fee on a channel (opener-side).
	 */
	proposeClosingFee(channelId: Buffer, signature: Buffer): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		this.applyClosingFeerate(channel);
		const actions = channel.proposeClosingFee(signature);
		this.processActions(peerPubkey, channel, actions);
		return { ok: true, actions };
	}

	/**
	 * Park a peer's channel_reestablish for a channel we have no record of,
	 * rather than answering it with the BOLT 1 error (issue #462). True when
	 * the message was parked and the caller must not reply.
	 *
	 * Declines, so the error goes out immediately, when: no hold window is
	 * configured; this peer has spent its quota (or the global backstop is
	 * reached); or this (peer, channel) already had its window and it elapsed.
	 * Parking is therefore bounded twice over, by the per-peer quota and by one
	 * window per key per process.
	 */
	private _holdUnknownChannelReestablish(
		peerPubkey: string,
		channelId: Buffer,
		payload: Buffer
	): boolean {
		const holdMs = this.config.unknownChannelReestablishHoldMs;
		if (
			holdMs === undefined ||
			!Number.isFinite(holdMs) ||
			holdMs <= 0 ||
			holdMs > MAX_UNKNOWN_REESTABLISH_HOLD_MS
		) {
			return false;
		}
		const key = `${peerPubkey}:${channelId.toString('hex')}`;
		const now = Date.now();
		const existing = this.heldUnknownReestablish.get(key);
		if (existing) {
			// The window is over: this key already had its one grace period, so
			// the peer gets the answer it would have got without the hold.
			if (now >= existing.deadline) return false;
			// Re-arm after a disconnect cleared the timer, for what is LEFT of
			// the original window. A flapping peer cannot renew it.
			if (!existing.timer) {
				existing.timer = this._armUnknownReestablishTimer(
					key,
					existing.deadline - now
				);
			}
			// A retransmit inside the window replaces the payload: the newest
			// message is the one worth replaying when the window ends.
			existing.payload = payload;
			return true;
		}
		if (
			this.heldUnknownReestablish.size >= MAX_HELD_UNKNOWN_REESTABLISH ||
			this._heldUnknownReestablishForPeer(peerPubkey) >=
				MAX_HELD_UNKNOWN_REESTABLISH_PER_PEER
		) {
			return false;
		}
		const deadline = now + holdMs;
		this.heldUnknownReestablish.set(key, {
			peerPubkey,
			channelId: Buffer.from(channelId),
			payload,
			deadline,
			timer: this._armUnknownReestablishTimer(key, holdMs)
		});
		this.emit('reestablish:held', peerPubkey, Buffer.from(channelId), deadline);
		return true;
	}

	/**
	 * Windows this peer has been granted, spent ones included. A linear scan
	 * over a map the global ceiling keeps small, run only when a reestablish
	 * names a channel we have no record of, which is rare outside a restore.
	 */
	private _heldUnknownReestablishForPeer(peerPubkey: string): number {
		let count = 0;
		for (const entry of this.heldUnknownReestablish.values()) {
			if (entry.peerPubkey === peerPubkey) count++;
		}
		return count;
	}

	/** One unref'd timer that replays a held reestablish when its window ends. */
	private _armUnknownReestablishTimer(
		key: string,
		delayMs: number
	): ReturnType<typeof setTimeout> {
		const timer = setTimeout(() => {
			const entry = this.heldUnknownReestablish.get(key);
			if (!entry) return;
			// Keep the entry as a tombstone: its elapsed deadline is what makes
			// the replay fall through to the error instead of re-parking.
			entry.timer = null;
			this._replayHeldReestablish(
				entry.peerPubkey,
				entry.channelId,
				entry.payload
			);
		}, delayMs);
		if (typeof timer.unref === 'function') timer.unref();
		return timer;
	}

	/**
	 * Deliver a parked reestablish now that its window has closed. Replayed
	 * rather than answered from scratch: if a restore installed the channel
	 * meanwhile the peer gets the real reestablish handling it has been waiting
	 * for, and if not the unknown-channel error goes out as it would have.
	 */
	private _replayHeldReestablish(
		peerPubkey: string,
		channelId: Buffer,
		payload: Buffer
	): void {
		// A channel that appeared DURING the window never went through peer
		// bring-up, so nobody has sent our channel_reestablish for it, and
		// shouldRetransmitReestablish() is false in AWAITING_REESTABLISH.
		// Without this the peer would be answered by a node that never
		// introduced itself, and BOLT 2 has both sides transmit (and wait)
		// before any other message for the channel. Ours goes first, exactly as
		// handlePeerReconnected would have sent it at bring-up.
		//
		// A double send cannot arise: parking means the channel was unknown at
		// that moment, and a disconnect retires the timer, so a reconnect
		// re-drives bring-up rather than reaching here.
		const channel = this.findChannelByChannelId(channelId);
		if (
			channel &&
			channel.getState() === ChannelState.AWAITING_REESTABLISH &&
			this.getPeerForChannel(channel.getChannelId() ?? channelId) === peerPubkey
		) {
			// Contained: this runs from a timer, where a throw would be an
			// uncaught exception rather than a failed message. The dispatch
			// below still runs, because the peer is owed an answer either way
			// (handleMessage has the same containment for the same reason).
			try {
				this.processActions(peerPubkey, channel, channel.createReestablish());
			} catch (err) {
				this.emit(
					'error',
					channel.getChannelId() ?? channelId,
					`Error reestablishing a channel restored under a hold: ${
						err instanceof Error ? err.message : String(err)
					}`
				);
			}
		}
		// Through handleMessage, never the handler directly: the parked id may
		// have been restored as ANOTHER peer's channel while the window ran, and
		// only the foreign-channel screen there keeps this sender's counters
		// away from a channel it does not own.
		this.handleMessage(peerPubkey, MessageType.CHANNEL_REESTABLISH, payload);
	}

	/**
	 * Reestablishes parked right now (issue #462), for the recovery status
	 * surface: which peer is waiting on which channel, and how long the
	 * operator has left to apply a capsule before the peer is told the
	 * channel is unknown. Reports only what is genuinely still waiting, so it
	 * excludes both spent windows and entries whose peer has disconnected (no
	 * armed timer): those describe a connection nobody is holding open.
	 */
	heldUnknownChannelReestablish(): Array<{
		peer: string;
		channelId: string;
		expiresAt: number;
	}> {
		const now = Date.now();
		const held: Array<{ peer: string; channelId: string; expiresAt: number }> =
			[];
		for (const entry of this.heldUnknownReestablish.values()) {
			if (!entry.timer || entry.deadline <= now) continue;
			held.push({
				peer: entry.peerPubkey,
				channelId: entry.channelId.toString('hex'),
				expiresAt: entry.deadline
			});
		}
		return held;
	}

	/** Drop every parked reestablish and its timer. */
	private _clearHeldUnknownReestablish(): void {
		for (const entry of this.heldUnknownReestablish.values()) {
			if (entry.timer) clearTimeout(entry.timer);
		}
		this.heldUnknownReestablish.clear();
	}

	private handleChannelReestablish(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeChannelReestablishMessage>;
		try {
			msg = decodeChannelReestablishMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'channel_reestablish',
				err
			);
			return;
		}

		// BOLT 1 reserves the all-zero channel_id for "all channels with this
		// peer", so a reestablish naming it identifies no channel and there is
		// no id we could answer under that means what we mean: the arm below
		// would send its "unknown or closed channel" error scoped to the
		// reserved id, which the peer reads as an instruction to fail EVERY
		// channel it has with us. Our own handleErrorMsg implements exactly
		// that rule, so one such message between two beignet nodes force-closes
		// every shared channel (issue #466). refuseInboundOpen and
		// Channel.wireErrorFor already refuse the same id for the same reason.
		//
		// Ahead of BOTH the lookup and the recovery hold below. An id that names
		// no channel is not a channel a Recovery Capsule can restore, so parking
		// it would spend one of the peer's hold windows, emit reestablish:held
		// and put an all-zero row on the recovery status surface for a message
		// that can never be answered. The decoder fixes channelId at 32 bytes,
		// so the reserved id is the only case canScopeWireError can refuse here.
		if (!canScopeWireError(msg.channelId)) {
			this.emitContained(
				'error',
				msg.channelId,
				'channel_reestablish dropped: channel_id is the reserved all-zero id'
			);
			return;
		}

		const channel = this.findChannelByChannelId(msg.channelId);

		// Recovery 5.7 (issue #462): a node that may still be an incomplete
		// restore target holds an unknown channel's reestablish instead of
		// failing it, because the state that would answer it may be minutes
		// away in a Recovery Capsule. Only the UNKNOWN case: the arm below
		// answers for channels this node has a record of.
		if (
			!channel &&
			this._holdUnknownChannelReestablish(peerPubkey, msg.channelId, payload)
		) {
			return;
		}

		// BOLT 2: reestablish for a channel we consider closed (or never knew)
		// must be answered with an error so the peer force-closes and stops
		// retrying it on every reconnect. Silently ignoring it leaves the peer
		// with a zombie channel it reestablishes forever, which is why the hold
		// above defers this reply rather than dropping it: an expired window
		// arrives back here.
		const deadState = channel?.getState();
		if (
			!channel ||
			deadState === ChannelState.FORCE_CLOSED ||
			deadState === ChannelState.CLOSED ||
			deadState === ChannelState.ERRORED
		) {
			// An ERRORED channel is failed but possibly not yet on chain (a channel
			// errored before force-close-on-error existed, or our broadcast is
			// still pending). The peer reestablishing proves it has NOT closed
			// either, so both sides may be waiting on the other: close ours now,
			// and say so instead of claiming the channel is unknown, since this
			// text is often the only diagnostic the peer's operator sees.
			const failedNotClosed = deadState === ChannelState.ERRORED;
			// Only the channel's own peer may trigger the close: a reestablish
			// quoting another peer's channel id still gets the error reply, but
			// must not drive a broadcast.
			const senderOwnsIt =
				channel !== undefined &&
				this.getPeerForChannel(channel.getChannelId() || msg.channelId) ===
					peerPubkey;
			if (failedNotClosed && senderOwnsIt) {
				this.emit(
					'channel:errored',
					channel!.getChannelId() || msg.channelId,
					'peer sent channel_reestablish for a failed channel'
				);
			}
			const wire = wireErrorPayloadFor(
				msg.channelId,
				failedNotClosed
					? 'channel failed; closing on chain'
					: 'unknown or closed channel'
			);
			if (wire) {
				this.sendMessage(peerPubkey, MessageType.ERROR, wire);
			}
			return;
		}

		// A reestablish AFTER this connection already reestablished the channel:
		// CLN restarts its channeld on the same connection after a tx_abort
		// exchange (splice recovery), and the fresh channeld sends — and expects —
		// a new channel_reestablish. Retransmit ours (once per connection), then
		// process theirs.
		if (channel.shouldRetransmitReestablish()) {
			this.processActions(peerPubkey, channel, channel.createReestablish());
		}

		const actions = channel.handleReestablish(msg);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: after reestablish, retransmit shutdown + closing_signed if closing
		const state = channel.getState();
		if (
			state === ChannelState.NEGOTIATING_CLOSING ||
			state === ChannelState.SHUTTING_DOWN
		) {
			// A channel restored MID-close from a Recovery Capsule without the
			// operator's acknowledgement must not resume the negotiation:
			// every remaining stage signs the split the capsule carries, and
			// even our retransmitted shutdown advertises a close we would then
			// refuse (issue #469). Refuse terminally here instead, so the 5.6
			// disposition asks the peer to close rather than the row sitting
			// in a state nothing else drives.
			if (channel.isMutualCloseHeld()) {
				this.processActions(
					peerPubkey,
					channel,
					channel.refuseHeldMutualClose()
				);
				return;
			}
			// Re-evaluate the negotiation path — features are per-connection —
			// and abandon any in-flight closing_complete (its closing_sig can
			// never arrive on the new connection; negotiation restarts per spec).
			channel.setSimpleClose(this.peerNegotiatedSimpleClose(peerPubkey));
			channel.resetSimpleCloseNegotiation();

			const fullState = channel.getFullState();
			if (
				fullState.localShutdownScript &&
				fullState.localShutdownScript.length > 0
			) {
				// buildShutdownRetransmit refreshes the MuSig2 closing nonce for
				// taproot channels (the pre-disconnect closing session is dead);
				// non-taproot channels get the plain shutdown unchanged.
				this.sendMessage(
					peerPubkey,
					MessageType.SHUTDOWN,
					encodeShutdownMessage(channel.buildShutdownRetransmit())
				);
			}
			if (state === ChannelState.NEGOTIATING_CLOSING) {
				if (channel.isSimpleClose()) {
					// Both roles restart the simple-close signing flow.
					this.startSimpleClose(peerPubkey, channel);
				} else if (channel.getRole() === ChannelRole.OPENER) {
					// Opener re-proposes closing_signed to resume fee negotiation
					// (proposeClosingFee re-derives the fee range, so a range
					// persisted from a stale/too-low feerate is replaced here).
					this.applyClosingFeerate(channel);
					const closingActions = channel.proposeClosingFee(
						(feeSatoshis: bigint) => this.signClosingTx(channel, feeSatoshis)
					);
					this.processActions(peerPubkey, channel, closingActions);
				}
			}
		}

		// A commitment_signed the durable state says we owe is released below
		// once the channel is back to NORMAL (issue 301). needsCommitment is
		// only ever persisted for legitimately owed signatures: our own
		// updates, and peer updates whose covering commitment_signed we
		// processed and revoked for (handleCommitmentSigned's two-phase
		// flags) — a peer update still awaiting the peer's own signature
		// never sets it. The dangerous interleavings stay covered by
		// autoSignAndSendCommitment's own gates: a commitment_signed of ours
		// the peer has not revoked defers on isAwaitingRemoteRevocation
		// (derived from persisted counters; the peer's retransmitted
		// revoke_and_ack releases it via handleRevokeAndAck), and with
		// nothing owed the call is a no-op. Without this release, a crash
		// after our revoke_and_ack reached the peer but before the counter
		// commitment_signed was built leaves BOTH sides with nothing to
		// retransmit per BOLT 2 — the peer simply waits for our signature,
		// forever, and the in-flight HTLC stalls to its CLTV expiry.

		// A channel RESTORED FROM PERSISTENCE that is back in NORMAL has
		// completed reestablish and can carry updates again, which is the
		// first moment its node-level repair pass can act
		// (redispatchUnresolvedReceivedHtlcs). Emitted at the tail so no later
		// step of this handler sits inside the listeners' callback window.
		//
		// Deliberately NOT 'channel:ready', and deliberately NOT for every
		// reestablishment. An ordinary TCP disconnect also puts a live channel
		// into AWAITING_REESTABLISH, so firing on every reconnect would re-run
		// the repair against node state that never went away, and that state
		// is not all idempotent: an accumulated inbound MPP part would be
		// counted a second time, letting a payer cycle the connection to reach
		// the declared total with less money than it sent. The repair exists
		// for exactly one situation, a process that lost its in-memory view,
		// so it is armed at restore and fires once.
		// Every state that can still SETTLE existing HTLCs, not NORMAL alone. A
		// restored SHUTTING_DOWN channel returns to SHUTTING_DOWN after
		// reestablish, so it never got the repair, and an unresolved committed
		// HTLC then kept the shutdown from ever reaching zero - while on a held
		// channel the automatic close that would otherwise end it is refused
		// (issue #469). The one-shot guard is unchanged: the repair is still
		// armed at restore and fires once.
		if (channel.canSettleHtlcs()) {
			this.emitRestoreRepairOnce(
				channel.getChannelId() ?? channel.getTemporaryChannelId()
			);
			// Unlike the restore repair above, this fires for EVERY completed
			// reestablishment, live reconnects included. Its listeners must
			// therefore be gated on durable facts alone (the node's
			// owed-upstream settle pass is: a forward linkage still on disk, a
			// known preimage, a committed inbound HTLC), never on the
			// assumption that in-memory state was lost.
			this.emit(
				'channel:reestablished',
				channel.getChannelId() ?? channel.getTemporaryChannelId()
			);
			// Settles deferred during a pre-disconnect quiescence session can
			// flow again (issue 430). Deferred out of this dispatch turn.
			const deferredSettleHex = channel.getChannelId()?.toString('hex');
			if (deferredSettleHex) {
				setImmediate(() => {
					this._drainDeferredSettles(deferredSettleHex);
				});
			}
			// Release a durably owed commitment_signed (see the note above the
			// settle check). Runs after the repair emissions so a fulfill/fail
			// they staged rides the same release. Re-check: a listener may have
			// force-closed the channel, and a shutting-down one still owes the
			// signature that lets its last HTLC resolve.
			const reestablishedId = channel.getChannelId();
			if (
				reestablishedId &&
				channel.canSettleHtlcs() &&
				!channel.isCollectingBatch()
			) {
				this.autoSignAndSendCommitment(reestablishedId);
			}
		}
	}

	/**
	 * Fire the restore repair for a channel that was loaded from persistence,
	 * at most once per process.
	 *
	 * The marker is cleared only after the listeners returned, so a repair
	 * that threw part way is retried on the next reestablishment rather than
	 * being silently dropped: EventEmitter is synchronous, which is what makes
	 * "the repair completed" observable here at all.
	 */
	private emitRestoreRepairOnce(channelId: Buffer): void {
		const idHex = channelId.toString('hex');
		if (!this.channelsAwaitingRestoreRepair.has(idHex)) return;
		try {
			this.emit('channel:restore-ready', channelId);
		} catch (err) {
			this.emit(
				'error',
				channelId,
				`restore repair failed, will retry on the next reestablish: ${
					(err as Error).message
				}`
			);
			return;
		}
		this.channelsAwaitingRestoreRepair.delete(idHex);
	}

	private handleStfu(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeStfuMessage>;
		try {
			msg = decodeStfuMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(peerPubkey, payload, 'stfu', err);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleStfuMessage(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * Initiate quiescence on a channel.
	 */
	initiateQuiescence(channelId: Buffer): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.initiateQuiescence();
		this.processActions(peerPubkey, channel, actions);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	// ─────────────── Splice ───────────────

	/**
	 * Whether the peer's init features negotiated splicing. Splicing requires
	 * BOTH option_quiesce (34/35) and option_splice (62/63) — sending stfu to a
	 * peer without option_quiesce makes it error and disconnect-loop (observed
	 * with CLN). Returns true when the peer's init is unknown (no peer manager
	 * attached, e.g. unit tests drive channels directly).
	 */
	private peerSupportsSplicing(peerPubkey: string): boolean {
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		if (!init) return true;
		return (
			init.features.hasFeature(Feature.QUIESCE) &&
			init.features.hasFeature(Feature.SPLICE)
		);
	}

	/**
	 * Whether option_simple_close (closing_complete/closing_sig) was negotiated
	 * with this peer: BOTH our advertised features and the peer's init must set
	 * it. Unlike peerSupportsSplicing, an unknown peer init defaults to FALSE —
	 * legacy closing_signed is the safe fallback every peer understands.
	 */
	/**
	 * Funding cap to enforce for operations with this peer. Lifted above the
	 * BOLT 2 2^24 sat cap only when option_wumbo is BOTH enabled locally
	 * (largeChannels) and advertised in the peer's init features; an unknown
	 * peer init defaults to the non-wumbo cap.
	 */
	private maxFundingForPeer(peerPubkey: string): bigint {
		if (!this.config.largeChannels) return MAX_FUNDING_SATOSHIS;
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		if (!init) return MAX_FUNDING_SATOSHIS;
		return init.features.hasFeature(Feature.LARGE_CHANNELS)
			? MAX_WUMBO_FUNDING_SATOSHIS
			: MAX_FUNDING_SATOSHIS;
	}

	private peerNegotiatedSimpleClose(peerPubkey: string): boolean {
		if (!this.config.localFeatures?.hasFeature(Feature.SIMPLE_CLOSE)) {
			return false;
		}
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		if (!init) return false;
		return init.features.hasFeature(Feature.SIMPLE_CLOSE);
	}

	private handleSpliceMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeSpliceMessage>;
		try {
			msg = decodeSpliceMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(peerPubkey, payload, 'splice', err);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		// Reject splice_init from a peer that never negotiated option_splice.
		// Routed through the channel-owned refusal (issue #371): a direct
		// tx_abort send would leave the quiescence a completed stfu handshake
		// established (feature views can disagree), freezing this side's HTLCs
		// until a disconnect, and would skip the tx_abort latch, drawing an
		// extra echo round. processActions surfaces the ERROR action as the
		// same 'error' event this branch used to emit.
		if (!this.peerSupportsSplicing(peerPubkey)) {
			const actions = channel.refuseSpliceInit(
				'option_splice not negotiated',
				'splice_init from peer without option_splice/option_quiesce'
			);
			this.processActions(peerPubkey, channel, actions);
			return;
		}

		// Splices can grow capacity, so refresh the (possibly wumbo-lifted) cap
		// from the peer's live init features before validating.
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const actions = channel.handleSplice(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleSpliceAckMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeSpliceAckMessage>;
		try {
			msg = decodeSpliceAckMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'splice_ack',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const actions = channel.handleSpliceAck(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleSpliceLockedMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeSpliceLockedMessage>;
		try {
			msg = decodeSpliceLockedMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'splice_locked',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleSpliceLocked(msg);
		this.processActions(peerPubkey, channel, actions);
		this.commitAfterSpliceIfComplete(channel);
	}

	private handleStartBatchMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeStartBatchMessage>;
		try {
			msg = decodeStartBatchMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'start_batch',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleStartBatch(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * When a splice has just completed (channel back to NORMAL on the new funding
	 * outpoint), drive a commitment_signed round so both sides hold a valid
	 * commitment spending the new funding output (force-close safety). completeSplice
	 * sets needsCommitment; during quiescence there are no other pending updates, so
	 * this only fires for the post-splice commitment.
	 */
	private commitAfterSpliceIfComplete(channel: Channel): void {
		if (
			channel.getState() !== ChannelState.NORMAL ||
			!channel.needsCommitment()
		) {
			return;
		}
		const channelId = channel.getChannelId();
		if (channelId) {
			this.autoSignAndSendCommitment(channelId);
		}
	}

	/**
	 * Initiate a splice on a channel (must already be quiescent).
	 */
	initiateSplice(
		channelId: Buffer,
		relativeSatoshis: bigint,
		fundingFeeratePerkw: number,
		locktime?: number
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// Fail fast BEFORE any stfu goes out: splicing a peer that never
		// advertised option_splice/option_quiesce makes it disconnect-loop.
		if (!this.peerSupportsSplicing(peerPubkey)) {
			const error =
				'peer does not support splicing (option_splice/option_quiesce not negotiated)';
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// Refresh the (possibly wumbo-lifted) funding cap before the splice-in
		// growth check inside initiateSplice.
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const actions = channel.initiateSplice(
			relativeSatoshis,
			fundingFeeratePerkw,
			locktime
		);
		this.processActions(peerPubkey, channel, actions);
		// Carry the channel's own reason out with the refusal: the callers
		// report it as the whole explanation, and without this a refusal from
		// initiateSplice itself (wrong state, splice in flight, reserve) left
		// them with an undefined message (issue #618).
		const errorAction = actions.find(
			(a): a is IErrorAction => a.type === ChannelActionType.ERROR
		);
		if (errorAction) {
			return { ok: false, actions, error: errorAction.message };
		}
		return { ok: true, actions };
	}

	/**
	 * Send splice_locked after splice tx confirmation.
	 */
	sendSpliceLocked(channelId: Buffer): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.sendSpliceLocked();
		this.processActions(peerPubkey, channel, actions);
		this.commitAfterSpliceIfComplete(channel);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	/**
	 * Initiate an RBF of a v2 (dual-funded) open's funding transaction
	 * (BOLT 2 tx_init_rbf; issue #360). Opener-only; permitted from the
	 * initial commitment exchange until channel_ready crosses or an attempt
	 * confirms. The channel's own guards produce the refusal reasons.
	 */
	initiateFundingRbf(
		channelId: Buffer,
		feeratePerKw: number,
		locktime?: number,
		newContribution?: {
			fundingSatoshis: bigint;
			topUpInputs?: ISpliceWalletInput[];
		}
	): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel =
			this.channels.get(idHex) || this.findChannelByChannelIdInTemp(channelId);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			// The wallet selection for a raise runs asynchronously, so the
			// channel can be gone by the time the request lands. Its coins were
			// frozen for a request that will never be made.
			this.releaseStaleSelectionPledges(newContribution?.topUpInputs ?? []);
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.releaseStaleSelectionPledges(
				channel.unregisteredV2TopUpInputs(newContribution?.topUpInputs ?? [])
			);
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		const actions = channel.initiateTxRbf(
			feeratePerKw,
			locktime,
			newContribution
		);
		// A refusal is a bare local ERROR with no wire message: report it to
		// the caller directly instead of dispatching it (processActions
		// treats ERROR as a channel failure, which a refused request is not).
		if (!actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)) {
			const firstError = actions.find(
				(a) => a.type === ChannelActionType.ERROR
			);
			// A refused request never reached the wire, so the coins selected
			// for it are free again — but ONLY the ones this open does not
			// already spend. The wallet can hand back a coin whose pledge
			// lapsed and re-offer it as a top-up, and releasing that would
			// unfreeze an input of the live funding tx. The channel filters;
			// anything it unregistered itself rides the dangling stash.
			if (newContribution?.topUpInputs?.length) {
				this.releaseStaleSelectionPledges(
					channel.unregisteredV2TopUpInputs(newContribution.topUpInputs)
				);
			}
			this.releaseDanglingV2Pledges(channel);
			return {
				ok: false,
				actions,
				error:
					firstError && 'message' in firstError
						? firstError.message
						: 'RBF request refused'
			};
		}
		this.processActions(peerPubkey, channel, actions);
		return { ok: true, actions };
	}

	/**
	 * Abort a splice operation.
	 */
	abortSplice(channelId: Buffer, reason?: string): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) {
			const error = `Peer not found for channel: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}

		// The splice:aborted event rides the channel's SPLICE_ABORTED action
		// through the dispatch below (issue #581): the channel arm that makes
		// the cancel decision is the one source of truth, so local aborts
		// that settle before the echo, disconnected aborts that never pass
		// through NORMAL, and repeated no-op cancels all behave correctly.
		const actions = channel.initiateSpliceAbort(reason);
		this.processActions(peerPubkey, channel, actions);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	// ─────────────── Dual Funding (v2) ───────────────

	/**
	 * Abort an in-flight dual-funded open: the v2 twin of abortSplice, for a
	 * host that started an open on a third party's behalf and needs to release
	 * the peer's half of it when its own exchange fails (issue #612). Without
	 * it a failed direct-funding session leaves a live negotiation the peer
	 * keeps holding open.
	 *
	 * The channel is resolved by permanent id, by the permanent id of a
	 * temp-resident channel, and by temporary id, because a v2 open answers to
	 * all three at different points of its life. Channel.abortDualFunding owns
	 * every refusal (post-tx_signatures, fully signed, RBF in flight); this
	 * only routes and dispatches.
	 *
	 * `pending` says the tx_abort went out and the attempt is still fully live:
	 * a RECORDED attempt tears down only on the peer's echo, and a disconnect
	 * before it resumes the negotiation. A caller holding an obligation to a
	 * third party must not read that as a release.
	 */
	abortDualFundedOpen(
		channelId: Buffer,
		reason?: string
	): { ok: boolean; error?: string; pending?: boolean } {
		const idHex = channelId.toString('hex');
		const channel =
			this.channels.get(idHex) ??
			this.findChannelByChannelIdInTemp(channelId) ??
			this.tempChannels.get(idHex);
		if (!channel) return { ok: false, error: `Channel not found: ${idHex}` };
		const peerPubkey = this.findPeerForChannel(channel);
		if (!peerPubkey) {
			return { ok: false, error: `Peer not found for channel: ${idHex}` };
		}
		const actions = channel.abortDualFunding(reason);
		// A refusal comes back as a bare local ERROR with no wire message, and
		// dispatching it would tear down a channel the refusal exists to
		// protect (the same read abortDualFunding's own callers apply).
		const refusal = actions.find((a) => a.type === ChannelActionType.ERROR) as
			| { message?: string }
			| undefined;
		if (
			refusal &&
			!actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		) {
			return {
				ok: false,
				error: refusal.message ?? 'dual-funding abort refused'
			};
		}
		try {
			this.processActions(peerPubkey, channel, actions);
		} finally {
			// A pre-record abort kills the negotiation on the spot, so nothing
			// will ever answer for this channel again and leaving it registered
			// strands an ERRORED lifecycle in the maps and in listChannels. The
			// echo normally reaches handleTxAbortMsg, which removes it there, but
			// a peer that never echoes (or a dispatch that throws) would leave it
			// until the disconnect sweep. A RECORDED attempt is not abandoned and
			// is deliberately untouched: it tears down on the echo.
			if (channel.isAbandonedV2Open()) {
				const id = channel.getChannelId() ?? channel.getTemporaryChannelId();
				if (this.removeCurrentChannelLifecycle(peerPubkey, channel)) {
					this.emitContained('channel:abandoned', id, 'v2 open aborted');
					this.releaseAbandonedV2Pledges(channel);
				}
			}
		}
		return { ok: true, pending: channel.isV2AbortAwaitingEcho() };
	}

	/**
	 * Open a dual-funded channel (v2) with a peer.
	 *
	 * opts.trusted opens it zero-conf (see openChannel): the zero_conf channel
	 * type is added to the negotiated type and both sides fast-track
	 * channel_ready after tx_signatures. Requires the peer in the trusted set.
	 *
	 * opts.contribution registers the opener's funding inputs (possibly
	 * carrying EXTERNAL ones, issue #572) BEFORE the open_channel2 is
	 * dispatched, so it wins over auto-funding in every message ordering,
	 * including a fully synchronous transport whose accept_channel2 is
	 * processed inside this call. Registering on the returned Channel after
	 * this call returns also works, but only when the accept cannot arrive
	 * first (any asynchronous transport). Not combinable with fundMax,
	 * fundingUtxos or a lease request; the node-level openChannelV2 refuses
	 * those combinations up front.
	 */
	createDualFundedChannel(
		peerPubkey: string,
		params: IDualFundingParams,
		opts?: {
			trusted?: boolean;
			contribution?: { inputs: ISpliceWalletInput[]; changeScript: Buffer };
		}
	): Channel {
		if (opts?.trusted && !this.zeroConfManager.canOpenZeroConfTo(peerPubkey)) {
			throw new Error(
				`Peer ${peerPubkey} is not in the trusted set; add it with addTrustedPeer (or let it register a JIT receive intent) before a trusted open`
			);
		}
		// V2 establishment is conditioned on NEGOTIATED option_dual_fund on
		// the explicit API too: the generic openChannel routes by these
		// bits, but openChannelV2 arrives here directly, and without the
		// same enforcement a masked vector (preferTaproot masks dual_fund
		// because taproot v2 signing does not exist) or an unsupporting
		// peer would still get an OPEN_CHANNEL2, a burned key index and a
		// retained temp channel for a negotiation that cannot complete.
		// With a real peer manager the peer must be connected, init-complete
		// and advertising the bit; a manager driven without one (unit
		// harnesses) negotiates for itself and is left alone.
		if (
			this.config.localFeatures !== undefined &&
			!this.config.localFeatures.hasFeature(Feature.DUAL_FUND)
		) {
			throw new Error(
				'Cannot open a dual-funded (v2) channel: this node does not advertise option_dual_fund'
			);
		}
		if (this.peerManager) {
			const peer = this.peerManager.getPeer(peerPubkey);
			if (!peer) {
				throw new Error(`Not connected to peer ${peerPubkey}`);
			}
			const remoteInit = peer.getRemoteInit();
			if (!remoteInit) {
				throw new Error(
					`Peer ${peerPubkey} has not completed init; cannot verify option_dual_fund`
				);
			}
			if (!remoteInit.features.hasFeature(Feature.DUAL_FUND)) {
				throw new Error(
					`Peer ${peerPubkey} did not advertise option_dual_fund`
				);
			}
		}
		// Resolve and validate the channel_type BEFORE any state exists for
		// it: a refused type must burn no key index and retain no channel.
		// CLN requires the channel_type TLV on open_channel2 (tx_abort:
		// "open_channel2 missing channel_type"). Default it to
		// static_remotekey plus anchors when preferred; the legacy open's
		// taproot default is deliberately NOT mirrored here, because taproot
		// v2 signing does not exist and validateV2ChannelType refuses the
		// bit outright (a preferTaproot node cannot reach this path through
		// the node API anyway: the global dual_fund mask throws above).
		let channelType = params.channelType;
		if (!channelType) {
			const typeFlags = FeatureFlags.empty();
			typeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			if (this.config.preferAnchors) {
				typeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			}
			channelType = typeFlags.toBuffer();
		}
		// Trusted zero-conf: the intent must ride in channel_type (BOLT 2
		// feature 50) or the acceptor treats this as an ordinary open and
		// answers with a real confirmation depth. BOLT 9 makes option_zeroconf
		// depend on option_scid_alias (a vector MUST include its transitive
		// dependencies), and BOLT 2 forbids announcing a channel whose type
		// carries option_scid_alias, so the open goes out private.
		let channelFlags = params.channelFlags;
		if (opts?.trusted) {
			const typeFlags = FeatureFlags.fromBuffer(channelType);
			typeFlags.setCompulsory(Feature.SCID_ALIAS);
			typeFlags.setCompulsory(Feature.ZERO_CONF);
			channelType = typeFlags.toBuffer();
		}
		// BOLT 2: a channel whose type carries option_scid_alias MUST NOT
		// be announced. Enforced on the RESOLVED type, so an explicit alias
		// type from a caller is forced private exactly like a trusted open,
		// instead of going out with the default announce flag.
		if (hasScidAliasChannelType(channelType)) {
			channelFlags = (channelFlags ?? 0x01) & ~0x01;
		}
		const typeRefusal = validateV2ChannelType(
			channelType,
			this.config.localFeatures,
			this.peerManager?.getPeer(peerPubkey)?.getRemoteInit()?.features
		);
		if (typeRefusal) {
			throw new Error(`Cannot open a dual-funded (v2) channel: ${typeRefusal}`);
		}
		// openChannelV2 arrives here rather than through openChannel, so the
		// guard has to be on both, or half the opens escape it.
		this._assertNamespaceCanRecordANewChannel();
		const chKeys = this.deriveKeysForNewChannel();
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: params.fundingSatoshis,
			pushMsat: 0n,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed
		});

		if (opts?.trusted) {
			state.zeroConfEnabled = true;
			state.trustedPeer = true;
			state.minimumDepth = 0;
		}

		const signer = this.makeSigner(
			chKeys.channelIndex,
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		channel.channelKeyIndex = chKeys.channelIndex;

		// The channel signs with chKeys, so it MUST advertise chKeys on the wire —
		// otherwise the funding pubkey (2-of-2) and the revocation basepoint (which
		// the v2 channel_id is derived from) would not match what the peer sees.
		// Override the caller's key material with the channel's own (mirrors the
		// acceptor path in handleOpenChannel2). In the common case (no per-channel
		// key deriver) these are already equal.
		if (hasScidAliasChannelType(channelType)) {
			state.announceChannel = false;
		}

		const alignedParams: IDualFundingParams = {
			...params,
			chainHash: params.chainHash ?? this.config.chainHash,
			channelType,
			channelFlags,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed,
			secondPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(chKeys.perCommitmentSeed, 0xffffffffffffn - 1n)
			)
		};

		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		// initiateOpenV2 derives the BOLT-2 temporary_channel_id from our
		// revocation basepoint (replacing the random stub), so key tempChannels
		// AFTER it runs — otherwise accept_channel2 (which echoes the derived id)
		// would not route back to this channel.
		const actions = channel.initiateOpenV2(alignedParams);
		const tempId = channel.getTemporaryChannelId().toString('hex');
		if (this.channelIdInUse(tempId)) {
			throw new Error(
				'Cannot open a dual-funded (v2) channel: temporary channel_id is already in use'
			);
		}
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);
		// Registered BEFORE the open_channel2 dispatch below: a synchronous
		// transport can deliver accept_channel2 inside processActions, and
		// autoFundDualFundedOpen must already see this contribution then.
		if (opts?.contribution) {
			channel.setDualFundingContribution(
				opts.contribution.inputs,
				opts.contribution.changeScript,
				alignedParams.fundingSatoshis,
				alignedParams.fundingFeeratePerkw
			);
		}
		try {
			this.processActions(peerPubkey, channel, actions);
		} catch (err) {
			// The registration above happens BEFORE the dispatch, so a throw here
			// leaves a temp channel and a peer binding for a negotiation whose
			// caller got an exception instead of the handle it would need to
			// unwind them. Nothing else can reach this channel again, so it goes
			// with the throw rather than answering an accept_channel2 nobody is
			// waiting for.
			this.removeCurrentTempChannel(peerPubkey, channel);
			this.releaseErroredTempV2Pledges(channel);
			throw err;
		}

		this.emit('channel:opened', channel.getTemporaryChannelId());
		return channel;
	}

	/**
	 * A refusal of a channel that already has a state machine: the wire half
	 * (when the id can carry one) followed by the local ERROR the dispatcher
	 * unwinds with. The manager-layer twin of Channel.refuseWithWireError, and
	 * the wire action LEADS for the same reason it does there.
	 *
	 * @param channelId - The scope the peer keys this negotiation by
	 * @param reason - Human-readable text for both halves
	 * @returns The actions to dispatch, never empty
	 */
	private refusalActions(channelId: Buffer, reason: string): ChannelAction[] {
		const payload = wireErrorPayloadFor(channelId, reason);
		const local: ChannelAction = {
			type: ChannelActionType.ERROR,
			message: reason
		};
		if (!payload) return [local];
		return [
			{
				type: ChannelActionType.SEND_MESSAGE,
				messageType: MessageType.ERROR,
				payload
			},
			local
		];
	}

	/** Refuse an inbound open before any channel state is retained. */
	private refuseInboundOpen(
		peerPubkey: string,
		channelId: Buffer,
		reason: string
	): void {
		// The open is still refused when the id cannot carry the wire half
		// (wireErrorPayloadFor says which ids those are), just silently: there
		// is no id we could answer under that means what we mean. Encoding sits
		// inside the guard with the send, so no failure on the way to the wire
		// can cost the local refusal diagnostic the finally owes.
		try {
			const payload = wireErrorPayloadFor(channelId, reason);
			if (payload) {
				this.sendMessage(peerPubkey, MessageType.ERROR, payload);
			}
		} catch {
			// The wire attempt already happened. Keep the local refusal diagnostic
			// singular even when a synchronous outbound observer throws.
		} finally {
			this.emitContained('error', channelId, reason);
		}
	}

	private handleOpenChannel2(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeOpenChannel2Message>;
		try {
			msg = decodeOpenChannel2Message(payload);
		} catch (err) {
			const detail = err instanceof Error ? err.message : String(err);
			const reason = `Undecodable open_channel2: ${detail}`;
			// Same shape as the open_channel guard: the negotiation id sits
			// at 32..64, after the chain_hash.
			if (payload.length >= 64) {
				this.refuseInboundOpen(
					peerPubkey,
					Buffer.from(payload.subarray(32, 64)),
					reason
				);
			} else {
				this.emitContained('error', null, reason);
			}
			return;
		}

		// V2 establishment is conditioned on NEGOTIATED option_dual_fund:
		// BOTH our advertised vector and the peer's init must carry it, so
		// an open_channel2 outside that contract is refused ahead of
		// everything with an effect: no keys derived, no temp channel, no
		// row. This is what makes a masked feature vector (quorum +
		// preferTaproot masks the bit because taproot v2 signing does not
		// exist) hold on the INBOUND side too. The refusal is PEER-VISIBLE:
		// a local event alone would leave the opener parked in
		// DUAL_FUNDING_V2 forever, so a wire error scoped to the temporary
		// channel id cancels the open on its side. A manager built without
		// a feature vector, or driven without a peer manager (unit
		// harnesses), negotiates for itself and is left alone.
		const localFeatures = this.config.localFeatures;
		const localLacks =
			localFeatures !== undefined &&
			!localFeatures.hasFeature(Feature.DUAL_FUND);
		const remoteInit = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		const remoteLacks =
			!!remoteInit && !remoteInit.features.hasFeature(Feature.DUAL_FUND);
		if (localLacks || remoteLacks) {
			const reason = localLacks
				? 'open_channel2 refused: this node does not advertise option_dual_fund'
				: 'open_channel2 refused: the peer did not advertise option_dual_fund';
			this.refuseInboundOpen(peerPubkey, msg.channelId, reason);
			return;
		}

		const expectedTempId = deriveV2TemporaryChannelId(msg.revocationBasepoint);
		if (!msg.channelId.equals(expectedTempId)) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.channelId,
				'open_channel2 refused: channel_id does not match the opener revocation basepoint'
			);
			return;
		}
		const proposedTempId = msg.channelId.toString('hex');
		if (
			this.tempChannels.has(proposedTempId) ||
			this.channels.has(proposedTempId) ||
			this.channelPeers.has(proposedTempId)
		) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.channelId,
				'open_channel2 refused: channel_id is already in use'
			);
			return;
		}

		// The PROPOSED channel_type is validated with the same timing and
		// visibility as the feature guard above: before keys are derived or
		// a temp channel is retained, with a wire error so the opener is
		// not parked in DUAL_FUNDING_V2 forever. Advertising dual_fund says
		// nothing about the commitment format the type asks for; a taproot
		// or otherwise unsupported type accepted here would echo through
		// ACCEPT_CHANNEL2 and then die at the commitment stage with a burnt
		// key index and a stuck retained channel.
		const typeRefusal = validateV2ChannelType(
			msg.channelType ?? null,
			localFeatures,
			remoteInit?.features
		);
		if (typeRefusal) {
			const reason = `open_channel2 refused: ${typeRefusal}`;
			this.refuseInboundOpen(peerPubkey, msg.channelId, reason);
			return;
		}
		// BOLT 2: scid_alias types are never announceable; an opener
		// pairing the alias type with the announce flag is refused with the
		// same wire visibility.
		const aliasAnnounce = scidAliasAnnounceRefusal(
			msg.channelType ?? null,
			(msg.channelFlags & 0x01) !== 0
		);
		if (aliasAnnounce) {
			const reason = `open_channel2 refused: ${aliasAnnounce}`;
			this.refuseInboundOpen(peerPubkey, msg.channelId, reason);
			return;
		}

		// Reject opens for a chain we do not operate on (the v1 open path
		// applies the same guard).
		if (
			this.config.chainHash &&
			msg.chainHash &&
			!msg.chainHash.equals(this.config.chainHash)
		) {
			this.refuseInboundOpen(
				peerPubkey,
				msg.channelId,
				`open_channel2 for unknown chain ${msg.chainHash.toString('hex')}`
			);
			return;
		}
		if (this._namespaceCannotRecordANewChannel()) {
			this.refuseInboundOpen(peerPubkey, msg.channelId, NAMESPACE_LOST_REFUSAL);
			return;
		}

		// Liquidity ads: when this open would make us SIGN a will_fund (the
		// buyer requested funds and we sell), the buyer-supplied blockheight
		// must be bounded BEFORE any key derivation or temp-channel retention.
		// The signed witness data writes lease_expiry = blockheight +
		// LEASE_DURATION_BLOCKS as a u32, so a wire-valid 0xffffffff would
		// throw out of signWillFund AFTER the temporary channel was stored:
		// repeated opens then accumulate retained channels with no
		// wire-visible answer (issue #536 review). The finer tip-window check
		// stays in the channel (it needs the channel's current height); this
		// bound only guarantees the arithmetic the signature commits to
		// cannot overflow.
		if (
			msg.requestFunds &&
			msg.requestFunds.requestedSats > 0n &&
			this.config.leaseRates &&
			this.config.nodePrivateKey &&
			!isTaprootChannel(msg.channelType ?? null)
		) {
			const bh = msg.requestFunds.blockheight;
			if (
				!Number.isInteger(bh) ||
				bh < 1 ||
				bh > 0xffffffff - LEASE_DURATION_BLOCKS
			) {
				this.refuseInboundOpen(
					peerPubkey,
					msg.channelId,
					`Buyer lease blockheight ${bh} is out of the acceptable range`
				);
				return;
			}
		}

		const chKeys = this.deriveKeysForNewChannel();
		const state = createAcceptorState({
			temporaryChannelId: msg.channelId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed,
			remoteBasepoints: {
				fundingPubkey: msg.fundingPubkey,
				revocationBasepoint: msg.revocationBasepoint,
				paymentBasepoint: msg.paymentBasepoint,
				delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
				htlcBasepoint: msg.htlcBasepoint,
				firstPerCommitmentPoint: msg.firstPerCommitmentPoint
			},
			remoteConfig: {
				dustLimitSatoshis: msg.dustLimitSatoshis,
				maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: msg.htlcMinimumMsat,
				toSelfDelay: msg.toSelfDelay,
				maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
				feeratePerKw: msg.commitmentFeeratePerkw
			}
		});

		const signer = this.makeSigner(
			chKeys.channelIndex,
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		channel.channelKeyIndex = chKeys.channelIndex;
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const tempId = msg.channelId.toString('hex');
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);

		// Trust-set membership only; handleOpenChannel2 flips zero-conf
		// semantics when (and only when) the opener proposed the zero_conf
		// channel type. Mirrors the v1 acceptor path.
		if (this.zeroConfManager.isTrustedPeer(peerPubkey)) {
			state.trustedPeer = true;
		}

		// Generate per-commitment points for local params
		const localParams: IDualFundingParams = {
			fundingSatoshis: 0n, // acceptor can contribute 0 or more
			fundingFeeratePerkw: msg.fundingFeeratePerkw,
			commitmentFeeratePerkw: msg.commitmentFeeratePerkw,
			dustLimitSatoshis: (this.config.localConfig || DEFAULT_CHANNEL_CONFIG)
				.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: (
				this.config.localConfig || DEFAULT_CHANNEL_CONFIG
			).maxHtlcValueInFlightMsat,
			htlcMinimumMsat: (this.config.localConfig || DEFAULT_CHANNEL_CONFIG)
				.htlcMinimumMsat,
			toSelfDelay: (this.config.localConfig || DEFAULT_CHANNEL_CONFIG)
				.toSelfDelay,
			maxAcceptedHtlcs: (this.config.localConfig || DEFAULT_CHANNEL_CONFIG)
				.maxAcceptedHtlcs,
			locktime: msg.locktime,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed,
			secondPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(chKeys.perCommitmentSeed, 0xffffffffffffn - 1n)
			)
		};

		// Liquidity ads (bLIP-0051): if the buyer requested funds and we sell
		// liquidity, contribute the requested amount and sign a will_fund over our
		// funding pubkey + the buyer's blockheight + channel_type + our rates.
		//
		// Script-enforced lease and simple taproot channels are MUTUALLY-EXCLUSIVE
		// commitment types (LND's taproot script builders have no lease/CLTV lock —
		// there is no interoperable "leased taproot" commitment). Never offer a lease
		// on a taproot channel; open it as a normal (unleased) taproot channel instead.
		if (
			msg.requestFunds &&
			// A 0-sat request is a degenerate lease: nothing to contribute and
			// nothing to charge for. Accept as a plain (unleased) open instead
			// of signing a will_fund and then failing to fund zero.
			msg.requestFunds.requestedSats > 0n &&
			this.config.leaseRates &&
			this.config.nodePrivateKey &&
			!isTaprootChannel(msg.channelType ?? null)
		) {
			const signature = signWillFund(
				chKeys.basepoints.fundingPubkey,
				msg.requestFunds.blockheight,
				this.config.leaseRates,
				this.config.nodePrivateKey
			);
			localParams.willFund = { signature, leaseRates: this.config.leaseRates };
			localParams.fundingSatoshis = msg.requestFunds.requestedSats;
		}

		if (localParams.willFund && msg.requestFunds) {
			// The lease contribution must actually be FUNDED: source wallet
			// inputs + change for it, register them on the channel (the
			// interactive-tx drive contributes and later signs them), and only
			// then answer with will_fund. No wallet coverage: withdraw the
			// offer and accept as a plain zero-contribution acceptor rather
			// than negotiating a funding tx we cannot fund.
			const requested = msg.requestFunds.requestedSats;
			const fp = this.fundingProvider;
			if (canSelectDualFundingInputs(fp)) {
				const isCurrentOpen = (): boolean =>
					this.tempChannels.get(tempId) === channel &&
					this.channelPeers.get(tempId) === peerPubkey;
				let selection: Promise<IDualFundingSelection>;
				try {
					// We are the ACCEPTOR here (answering open_channel2), so our fee
					// share excludes the common fields and the shared funding output.
					// The session does not exist until handleOpenChannel2 runs below,
					// hence the literal rather than session.isInitiator().
					selection = selectDualFundingContribution(
						fp,
						requested,
						msg.fundingFeeratePerkw,
						false
					);
				} catch (err) {
					selection = Promise.reject(err);
				}
				void selection
					.then(
						({ inputs, changeScript }) => {
							// Wallet selection can outlive a disconnect and same-id retry.
							// A stale completion must not mutate or dispatch for its old
							// channel; its just-pledged inputs were never registered
							// anywhere, so their pledges release at once (issue #311).
							if (!isCurrentOpen()) {
								this.releaseStaleSelectionPledges(inputs);
								return;
							}
							channel.setDualFundingContribution(
								inputs,
								changeScript,
								requested,
								msg.fundingFeeratePerkw
							);
							const actions = channel.handleOpenChannel2(msg, localParams);
							this.processActions(peerPubkey, channel, actions);
						},
						(err) => {
							if (!isCurrentOpen()) return;
							this.emitContained(
								'error',
								msg.channelId,
								`Lease contribution not funded (${
									(err as Error)?.message ?? err
								}); accepting without will_fund`
							);
							// The diagnostic observer can synchronously disconnect and replace
							// this open, so ownership must be checked again after it returns.
							if (!isCurrentOpen()) return;
							delete localParams.willFund;
							localParams.fundingSatoshis = 0n;
							// Withdrawn lease → plain zero-contribution accept; register
							// the empty contribution so the drive still answers the
							// opener's turns (see below).
							channel.setDualFundingContribution(
								[],
								Buffer.alloc(0),
								0n,
								msg.fundingFeeratePerkw
							);
							const actions = channel.handleOpenChannel2(msg, localParams);
							this.processActions(peerPubkey, channel, actions);
						}
					)
					.catch((err) => {
						// Dispatch failures are not wallet-selection failures and must not
						// run the fallback a second time.
						this.emitContained(
							'error',
							msg.channelId,
							`Lease open dispatch failed: ${(err as Error)?.message ?? err}`
						);
					});
				return;
			}
			// No funding provider: keep the legacy behavior (the embedder — or a
			// test harness — drives the contribution itself via addTxInput).
		} else {
			// Plain zero-contribution accept. Register the EMPTY contribution so
			// the interactive-tx drive takes our turns: with nothing to add it
			// answers each opener message with tx_complete. Without a registered
			// contribution the drive is a no-op (reserved for the legacy
			// embedder-driven flow), the acceptor never completes, and the
			// negotiation deadlocks with both sides parked in DUAL_FUNDING_V2 —
			// which is exactly how every beignet-to-beignet v2 open hung (CLN
			// acceptors reply on their own, so interop tests never caught it).
			channel.setDualFundingContribution(
				[],
				Buffer.alloc(0),
				0n,
				msg.fundingFeeratePerkw
			);
		}

		const actions = channel.handleOpenChannel2(msg, localParams);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleAcceptChannel2Msg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeAcceptChannel2Message>;
		try {
			msg = decodeAcceptChannel2Message(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'accept_channel2',
				err
			);
			return;
		}
		const tempId = msg.channelId.toString('hex');
		const channel = this.tempChannels.get(tempId);
		if (!channel) {
			this.emit('error', null, 'Unknown channel_id in accept_channel2');
			return;
		}
		if (this.channelPeers.get(tempId) !== peerPubkey) {
			this.emit(
				'error',
				msg.channelId,
				'Ignoring accept_channel2 from a peer that does not own the open'
			);
			return;
		}

		// Liquidity ads (bLIP-0051): if we requested funds and the seller answered
		// with a will_fund, verify the seller signed these exact lease terms before
		// trusting the lease. A bad signature fails the open.
		const session = channel.getDualFundingSession();
		const requestFunds = session?.getRequestFunds();
		let leaseEvent:
			| {
					channelId: Buffer;
					requestedSats: bigint;
					leaseRates: ILeaseRates;
					sellerFundingSatoshis: bigint;
			  }
			| undefined;
		if (msg.willFund && requestFunds) {
			const ok = verifyWillFund(
				msg.willFund.signature,
				msg.willFund.leaseRates,
				Buffer.from(peerPubkey, 'hex'),
				msg.fundingPubkey,
				requestFunds.blockheight
			);
			if (!ok) {
				const reason = 'Invalid will_fund signature';
				this.processActions(
					peerPubkey,
					channel,
					this.refusalActions(msg.channelId, reason)
				);
				return;
			}
			leaseEvent = {
				channelId: msg.channelId,
				requestedSats: requestFunds.requestedSats,
				leaseRates: msg.willFund.leaseRates,
				sellerFundingSatoshis: msg.fundingSatoshis
			};
		}

		const actions = channel.handleAcceptChannel2(msg);
		const hasError = actions.some((a) => a.type === ChannelActionType.ERROR);
		if (actions.length > 0) {
			this.processActions(peerPubkey, channel, actions);
		}

		// Start the driver before the informational event. A throwing observer
		// must not prevent the wallet selection the peer is waiting on.
		if (!hasError) {
			const isCurrentOpen = (): boolean =>
				this.tempChannels.get(tempId) === channel &&
				this.channelPeers.get(tempId) === peerPubkey;
			this.autoFundDualFundedOpen(channel, peerPubkey);
			if (!isCurrentOpen()) return;
			if (leaseEvent) {
				this.emitContained('channel:lease', leaseEvent);
				if (!isCurrentOpen()) return;
			}
			if (isCurrentOpen()) {
				this.emitContained('channel:accepted', channel, peerPubkey);
			}
		}
	}

	/**
	 * Fund the INITIATOR's side of a v2 open from the wallet, mirroring the
	 * lease-seller path in handleOpenChannel2: source wallet inputs + change
	 * via the funding provider, register them as the channel's contribution,
	 * and kick off the interactive tx (BOLT 2: the initiator sends the first
	 * tx_add_input, so without this the open stalls right after
	 * accept_channel2). Without a funding provider the legacy behavior holds:
	 * the embedder drives the contribution itself via addTxInput.
	 *
	 * The on-chain contribution is our funding share plus the lease fee when
	 * we are leasing inbound liquidity, which is paid through the funding
	 * transaction (see handleAcceptChannel2), not from channel balance.
	 */
	private autoFundDualFundedOpen(channel: Channel, peerPubkey: string): void {
		const fp = this.fundingProvider;
		const session = channel.getDualFundingSession();
		const local = session?.getLocalParams();
		if (!session || !session.isInitiator() || !local) return;
		// A contribution the embedder already registered (possibly carrying an
		// EXTERNAL input, issue #572) wins outright: selecting on top of it
		// would overwrite it. It still must DRIVE on accept_channel2 (the
		// initiator sends the first tx_add_input), and this arm sits before
		// the provider checks so a provider-less manager drives it too.
		if (channel.hasDualFundingContribution()) {
			const driveActions = channel.beginDualFundingContribution();
			this.processActions(peerPubkey, channel, driveActions);
			return;
		}
		const tempId = channel.getTemporaryChannelId().toString('hex');
		const isCurrentOpen = (): boolean =>
			this.tempChannels.get(tempId) === channel &&
			this.channelPeers.get(tempId) === peerPubkey;
		// A max open contributes EVERY spendable UTXO (change nets out to zero
		// against the committed amount); a fixed open covers amount + fee.
		// Without the matching provider method the legacy behavior holds: the
		// embedder drives the contribution itself via addTxInput.
		const fundMax = local.fundMax === true;
		if (
			fundMax
				? !fp?.selectMaxDualFundingInputs
				: !canSelectDualFundingInputs(fp)
		) {
			// Directed funding (fundingUtxos) cannot fall back to the legacy
			// caller-driven flow: the caller named specific coins, so a
			// provider that cannot select is a funding failure the peer must
			// hear about, never a silent stall (issue #572 review).
			if (local.fundingUtxos) {
				this.emitContained(
					'error',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					'v2 open not funded: fundingUtxos requires a funding provider that can select wallet inputs'
				);
				if (!isCurrentOpen()) return;
				const abortActions = channel.abortDualFunding(
					'opener funding unavailable: fundingUtxos requires a wallet-selection funding provider'
				);
				this.processActions(peerPubkey, channel, abortActions);
			}
			return;
		}

		const state = channel.getFullState();
		const contributionSats = local.fundingSatoshis + (state.leaseFeeSats ?? 0n);
		const feeratePerKw = local.fundingFeeratePerkw;
		let selection: Promise<IDualFundingSelection>;
		try {
			selection = fundMax
				? fp!.selectMaxDualFundingInputs!()
				: selectDualFundingContribution(
						fp!,
						contributionSats,
						feeratePerKw,
						true,
						false,
						local.fundingUtxos
				  );
		} catch (err) {
			selection = Promise.reject(err);
		}

		void selection
			.then(
				({ inputs, changeScript }) => {
					// A stale completion's just-pledged inputs were never registered
					// anywhere, so their pledges release at once (issue #311).
					if (!isCurrentOpen()) {
						this.releaseStaleSelectionPledges(inputs);
						return;
					}
					// The embedder registered a contribution while the wallet
					// selection was in flight (a synchronous transport runs
					// accept_channel2 inside createDualFundedChannel, so this
					// race is real). The registered one wins; of the selected
					// coins, only those the winning contribution does NOT
					// spend release their pledges. The overlap set can be
					// non-empty (the wallet legitimately re-offers a coin whose
					// pledge TTL lapsed), and releasing a coin the live funding
					// tx depends on lets the next wallet spend orphan the
					// channel (issue #572 review).
					if (channel.hasDualFundingContribution()) {
						// Best-effort cleanup, never a gate on driving: the
						// overlap helper isolates prevTx parsing PER INPUT
						// (issue #581), so a malformed coin in a third-party
						// provider's result neither throws past the drive nor
						// discards the cleanup of the parseable coins beside
						// it. What the parse cannot name, the TTL releases.
						this.releaseStaleSelectionPledges(
							channel.unregisteredV2TopUpInputs(inputs)
						);
						const driveActions = channel.beginDualFundingContribution();
						this.processActions(peerPubkey, channel, driveActions);
						return;
					}
					// Directed selection (fundingUtxos) is a promise to the
					// caller, not a hint: a provider that ignored the trailing
					// opts (a third-party implementation predating them) must
					// not fund the open with arbitrary coins. Verify before
					// registering; a violation is a funding failure and the
					// unusable selection's pledges release (issue #572 review).
					if (local.fundingUtxos) {
						const directedError = verifyDirectedSelection(
							inputs,
							local.fundingUtxos
						);
						if (directedError) {
							this.releaseStaleSelectionPledges(inputs);
							this.emitContained(
								'error',
								channel.getChannelId() ?? channel.getTemporaryChannelId(),
								`v2 open not funded: ${directedError}`
							);
							if (!isCurrentOpen()) return;
							const abortActions = channel.abortDualFunding(
								`opener funding unavailable: ${directedError}`
							);
							this.processActions(peerPubkey, channel, abortActions);
							return;
						}
					}
					channel.setDualFundingContribution(
						inputs,
						changeScript,
						contributionSats,
						feeratePerKw
					);
					const driveActions = channel.beginDualFundingContribution();
					this.processActions(peerPubkey, channel, driveActions);
				},
				(err) => {
					if (!isCurrentOpen()) return;
					// The embedder registered a contribution while the wallet
					// selection was in flight: the selection's failure is moot,
					// the registered contribution funds the open. Drive it
					// instead of aborting a perfectly viable open (issue #572
					// review).
					if (channel.hasDualFundingContribution()) {
						const driveActions = channel.beginDualFundingContribution();
						this.processActions(peerPubkey, channel, driveActions);
						return;
					}
					const reason = (err as Error)?.message ?? err;
					// The opener cannot downgrade to a zero contribution. Report the
					// wallet failure, then abort so the peer does not wait indefinitely.
					this.emitContained(
						'error',
						channel.getChannelId() ?? channel.getTemporaryChannelId(),
						`v2 open not funded: ${reason}`
					);
					// The diagnostic observer can synchronously remove or replace the
					// open, so check ownership again before changing channel state.
					if (!isCurrentOpen()) return;
					const abortActions = channel.abortDualFunding(
						`opener funding unavailable: ${reason}`
					);
					this.processActions(peerPubkey, channel, abortActions);
				}
			)
			.catch((err) => {
				// Dispatch failures are not wallet-selection failures and must not
				// abort a contribution whose wire actions may already be delivered.
				this.emitContained(
					'error',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					`v2 open dispatch failed: ${(err as Error)?.message ?? err}`
				);
			});
	}

	private handleTxAddInput(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxAddInputMessage>;
		try {
			msg = decodeTxAddInputMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_add_input',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddInput(msg);
		// Kick off the chain check before dispatching replies: a synchronous
		// transport can drive the whole negotiation inside processActions, and
		// the session gate below must see the state right after the add.
		this.verifyPeerFundingInput(peerPubkey, channel, msg);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * Kick off the optional chain verification of a v2 peer's tx_add_input
	 * prevout (issue #311). Fire and forget: the negotiation proceeds while
	 * the backend answers, and only a conclusive 'spent-or-missing' verdict
	 * acts (applyPeerInputVerdict). Scoped to v2 open negotiations; splice
	 * inputs (shared or wallet) never satisfy the session gate.
	 */
	private verifyPeerFundingInput(
		peerPubkey: string,
		channel: Channel,
		msg: ITxAddInputMessage
	): void {
		const verify = this.config.verifyRemoteFundingInput;
		if (!verify) return;
		// Splice shared input: its outpoint is the channel's own funding
		// output, validated against the channel state instead of the chain.
		if (msg.sharedInputTxid) return;
		const session = channel.getDualFundingSession();
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return;
		}
		// A prev_tx the channel already rejected (unparseable, vout out of
		// range) never reaches the builder; nothing to verify.
		let prevTx: bitcoin.Transaction;
		try {
			prevTx = bitcoin.Transaction.fromBuffer(msg.prevTx);
		} catch {
			return;
		}
		const vout = msg.prevTxVout;
		if (!prevTx.outs[vout]) return;
		const txid = Buffer.from(prevTx.getHash());
		const key = `${txid.toString('hex')}:${vout}`;
		let seen = this._verifiedPeerInputs.get(channel);
		if (!seen) {
			seen = new Set();
			this._verifiedPeerInputs.set(channel, seen);
		}
		if (seen.has(key)) return;
		seen.add(key);
		void verify({ txid, vout, scriptPubKey: prevTx.outs[vout].script })
			.then((verdict) =>
				this.applyPeerInputVerdict(
					verdict,
					peerPubkey,
					channel,
					session,
					msg.channelId,
					txid,
					vout
				)
			)
			.catch(() => {
				// Verification failure is 'unknown': fail open.
			});
	}

	/**
	 * Act on a chain verdict for a peer funding input (issue #311). Only a
	 * conclusive 'spent-or-missing' aborts, and only when the channel, the
	 * session and the contributed outpoint all still stand exactly as they
	 * did when the query left. Anything already past the point where an
	 * abort is allowed (tx_signatures released, funding tx staged) is left
	 * to the funding-missing watchdog and the pledge TTL.
	 */
	private applyPeerInputVerdict(
		verdict: 'unspent' | 'spent-or-missing' | 'unknown',
		peerPubkey: string,
		channel: Channel,
		session: DualFundingSession,
		channelId: Buffer,
		txid: Buffer,
		vout: number
	): void {
		if (verdict !== 'spent-or-missing') return;
		// Instance identity: the id must still resolve to this very object,
		// registered to this very peer. A disconnect plus a same-id retry
		// replaces the instance; a late verdict must not touch its successor.
		const found =
			this.findChannelByChannelId(channelId) ||
			this.findChannelByChannelIdInTemp(channelId) ||
			this.findTempChannel(channelId);
		if (found !== channel) return;
		const idHex = channelId.toString('hex');
		const registeredPeer = this.channelPeers.get(idHex);
		if (registeredPeer !== undefined && registeredPeer !== peerPubkey) return;
		// A verdict landing after a disconnect must not act: markForReestablish
		// keeps the session of a recorded open (it resumes over reestablish),
		// so the guards below would pass, and the abort would re-arm the
		// _v2AbortPending latch the disconnect just cleared while its tx_abort
		// is lost with the connection, wedging the resumed exchange.
		if (channel.getState() === ChannelState.AWAITING_REESTABLISH) return;
		// Session identity: a peer abort or completed open nulls or replaces
		// the session.
		if (channel.getDualFundingSession() !== session) return;
		// The outpoint must still be contributed. RBF resets the builder
		// inside the SAME session object, so builder membership, not session
		// identity, is the staleness guard for a renegotiated attempt.
		const stillContributed = session
			.getTxBuilder()
			?.getInputs()
			.some(
				(i) =>
					!i.isShared && i.prevTxid.equals(txid) && i.prevOutputIndex === vout
			);
		if (!stillContributed) return;
		const displayOutpoint = `${Buffer.from(txid)
			.reverse()
			.toString('hex')}:${vout}`;
		const reason = `peer tx_add_input ${displayOutpoint} not found unspent on chain (issue #311)`;
		// Too late to abort (BOLT 2: no tx_abort after tx_signatures; a staged
		// fully signed tx owes the network a broadcast). Report and leave the
		// outcome to the watchdog; dispatching the refusal ERROR instead would
		// wrongly tear down the temp channel. A post-signatures RBF
		// renegotiation is the exception: the verdict concerns the
		// REPLACEMENT negotiation (nothing signed yet), which abortDualFunding
		// unwinds attempt-scoped back to the retained attempt.
		const st = channel.getFullState();
		const renegotiating =
			!!st.v2InFlight &&
			!!st.dualFundingSession &&
			typeof st.v2InFlight.rbfAttempt === 'number' &&
			st.v2InFlight.rbfAttempt !== st.dualFundingSession.getRbfCount();
		if (
			!renegotiating &&
			(st.v2InFlight?.sentTxSignatures || st.pendingFundingTxHex)
		) {
			this.emitContained(
				'error',
				channel.getChannelId() ?? channel.getTemporaryChannelId(),
				`${reason}, detected after signature release`
			);
			return;
		}
		const actions = channel.abortDualFunding(reason);
		// A refusal (e.g. an RBF request awaiting its answer) comes back as a
		// bare local ERROR with no wire message: swallow it, fail open.
		if (!actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)) {
			return;
		}
		this.emitContained(
			'error',
			channel.getChannelId() ?? channel.getTemporaryChannelId(),
			reason
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAddOutput(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxAddOutputMessage>;
		try {
			msg = decodeTxAddOutputMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_add_output',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveInput(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxRemoveInputMessage>;
		try {
			msg = decodeTxRemoveInputMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_remove_input',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveInput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveOutput(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxRemoveOutputMessage>;
		try {
			msg = decodeTxRemoveOutputMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_remove_output',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxCompleteMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxCompleteMessage>;
		try {
			msg = decodeTxCompleteMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_complete',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxComplete();
		// tx_complete may trigger our v2 commitment_signed, which sets the
		// derived channelId — promote before processActions so PERSIST_STATE
		// resolves the channel by its permanent id.
		this._promoteV2ChannelIfReady(peerPubkey, channel);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxSignaturesMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxSignaturesMessage>;
		try {
			msg = decodeTxSignaturesMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_signatures',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxSignatures(msg);
		this._promoteV2ChannelIfReady(peerPubkey, channel);
		this.processActions(peerPubkey, channel, actions);
	}

	/**
	 * Promote a v2 (dual-funded) channel from tempChannels to the permanent map.
	 * The boundary is the point of no return: the batch that creates the
	 * durable v2InFlight record (our initial commitment_signed) also first
	 * persists the row under the permanent id, and from then on the channel
	 * must be resolvable by findChannelByChannelId / getChannelsByPeer so a
	 * disconnect reestablishes instead of aborting (BOLT 2: the signature
	 * exchange resumes over next_funding). Before the record exists the
	 * channel stays in tempChannels, where handlePeerDisconnected's sweep
	 * correctly aborts it. Routing works either way: commitment_signed is
	 * found via findChannelByChannelIdInTemp (derived id) and tx_signatures
	 * via findTempChannel (temporary id). Idempotent.
	 */
	private _promoteV2ChannelIfReady(peerPubkey: string, channel: Channel): void {
		const cid = channel.getChannelId();
		if (!cid) return;
		// A zero-conf v2 open fast-tracks channel_ready inside the same action
		// batch that completes the funding, so by promotion time the channel may
		// already be past AWAITING_FUNDING_CONFIRMED.
		const st = channel.getState();
		if (
			st !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			st !== ChannelState.AWAITING_CHANNEL_READY &&
			st !== ChannelState.NORMAL &&
			!(
				st === ChannelState.AWAITING_TX_SIGNATURES &&
				channel.getFullState().v2InFlight != null
			)
		) {
			return;
		}
		this.promoteChannelLifecycle(peerPubkey, channel);
	}

	private handleTxInitRbfMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxInitRbfMessage>;
		try {
			msg = decodeTxInitRbfMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_init_rbf',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxInitRbf(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAckRbfMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxAckRbfMessage>;
		try {
			msg = decodeTxAckRbfMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_ack_rbf',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAckRbf(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAbortMsg(peerPubkey: string, payload: Buffer): void {
		let msg: ReturnType<typeof decodeTxAbortMessage>;
		try {
			msg = decodeTxAbortMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'tx_abort',
				err
			);
			return;
		}
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAbort();
		const progress = newDispatchProgress();
		let dispatchCompleted = false;
		try {
			this.processActions(peerPubkey, channel, actions, progress);
			dispatchCompleted = true;
		} finally {
			// Forget a dead open only after its full teardown batch completed, or
			// after the tx_abort transport call was attempted. A persist or
			// transition failure before that point must retain the recoverable row.
			const allActionsCompleted =
				actions.length > 0 && progress.completedIndex >= actions.length - 1;
			const cancellationAttempted = progress.attemptedMessageTypes.has(
				MessageType.TX_ABORT
			);
			if (
				channel.isAbandonedV2Open() &&
				((!progress.sendsWithheld &&
					(dispatchCompleted || allActionsCompleted)) ||
					cancellationAttempted) &&
				this.removeCurrentChannelLifecycle(peerPubkey, channel)
			) {
				this.emitContained(
					'channel:abandoned',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					'v2 open aborted'
				);
				this.releaseAbandonedV2Pledges(channel);
			}
		}
		// splice:aborted now rides the channel's SPLICE_ABORTED action through
		// processActions (issue #581): the peer-initiated unwind appends it
		// inside abortSplice, and the echo of OUR local abort appends nothing
		// (the local initiateSpliceAbort already signaled), so the event
		// fires exactly once per attempt in every ordering.
	}

	private handleAnnouncementSignaturesMsg(
		peerPubkey: string,
		payload: Buffer
	): void {
		let msg: ReturnType<typeof decodeAnnouncementSignaturesMessage>;
		try {
			msg = decodeAnnouncementSignaturesMessage(payload);
		} catch (err) {
			this.failChannelForUndecodablePayload(
				peerPubkey,
				payload,
				'announcement_signatures',
				err
			);
			return;
		}
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) {
			this.emit('error', null, 'Unknown channel_id in announcement_signatures');
			return;
		}

		const state = channel.getFullState();
		const localNodeId = this.config.nodePrivateKey
			? getPublicKey(this.config.nodePrivateKey)
			: this.config.localBasepoints.fundingPubkey;
		const remoteNodeId = Buffer.from(peerPubkey, 'hex');

		const actions = channel.handleAnnouncementSignatures(
			msg,
			localNodeId,
			remoteNodeId,
			state.localAnnouncementNodeSig ?? undefined,
			state.localAnnouncementBitcoinSig ?? undefined
		);
		this.processActions(peerPubkey, channel, actions);

		// If we received remote sigs but haven't sent ours yet (ChainWatcher
		// didn't fire announcement:depth), signal that signing is needed so
		// LightningNode can trigger it with the funding private key.
		const updated = channel.getFullState();
		if (updated.shortChannelId) {
			this.emit('channel:scid-assigned', msg.channelId, updated.shortChannelId);
		}
		if (
			updated.announcementSigsReceived &&
			!updated.announcementSigsSent &&
			updated.shortChannelId
		) {
			this.emit(
				'announcement:needs-signing',
				msg.channelId,
				updated.shortChannelId
			);
		}
	}

	/**
	 * Trigger announcement depth reached on a channel (called by LightningNode
	 * when the funding transaction reaches 6 confirmations).
	 */
	triggerAnnouncementDepth(
		channelId: Buffer,
		blockHeight: number,
		txIndex: number,
		localNodeId: Buffer,
		signAnnouncement: (data: Buffer) => { nodeSig: Buffer; bitcoinSig: Buffer }
	): void {
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const peerPubkey = this.channelPeers.get(channelId.toString('hex'));
		if (!peerPubkey) return;
		const remoteNodeId = Buffer.from(peerPubkey, 'hex');

		const actions = channel.handleAnnouncementDepthReached(
			blockHeight,
			txIndex,
			localNodeId,
			remoteNodeId,
			signAnnouncement
		);

		// Store local sigs on the state for later use when remote sigs arrive
		const state = channel.getFullState();
		if (state.announcementSigsSent) {
			// Sigs are now stored on the state by handleAnnouncementDepthReached
		}

		this.processActions(peerPubkey, channel, actions);

		// handleAnnouncementDepthReached is where the real SCID is first computed,
		// for private channels too (it assigns before returning early on those).
		// LightningNode needs it to accept forwards addressed by the SCID we publish.
		const scid = channel.getFullState().shortChannelId;
		if (scid) {
			this.emit('channel:scid-assigned', channelId, scid);
		}
	}

	/**
	 * Void a channel whose funding tx vanished from mempool AND chain before
	 * confirming (evicted or an input double-spent): the channel never existed
	 * on the network, so there is nothing to close and it is simply dropped.
	 * The coins contributed to the funding remain (or return) onchain.
	 * Returns false if the channel is unknown.
	 */
	voidChannel(channelId: Buffer): boolean {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) return false;
		// A channel that never existed on the network has no peer left to tell
		// anything, so anything held for it goes with it.
		this.purgeBarrierQueue(idHex);
		this.channels.delete(idHex);
		this.channelPeers.delete(idHex);
		this.channelsAwaitingRestoreRepair.delete(idHex);
		return true;
	}

	private handleErrorMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeErrorMessage(payload);
		const channelIdHex = msg.channelId.toString('hex');
		const errorText = msg.data.toString('utf8');

		// BOLT 1: an all-zero (or absent) channel_id refers to ALL channels with
		// the sending node, and every one of them must be failed. Only the
		// sender's own channels: an error from one peer must never touch a
		// channel belonging to another.
		const isConnectionWide =
			msg.channelId.length === 0 || msg.channelId.every((b) => b === 0);
		if (isConnectionWide) {
			for (const channel of this.getChannelsByPeer(peerPubkey)) {
				this.failChannelByError(channel, `Remote error: ${errorText}`);
			}
			// Unfunded negotiations with this peer die too; nothing is on chain,
			// so they are simply forgotten. A dead v2 open's funding pledges
			// release with it (issue #311, releaseErroredTempV2Pledges).
			for (const tempId of [...this.tempChannels.keys()]) {
				if (this.channelPeers.get(tempId) !== peerPubkey) continue;
				const tempChannel = this.tempChannels.get(tempId);
				this.tempChannels.delete(tempId);
				this.channelPeers.delete(tempId);
				if (tempChannel) this.releaseErroredTempV2Pledges(tempChannel);
			}
			this.emit('error', msg.channelId, `Remote error: ${errorText}`);
			return;
		}

		// A v2 open begins under its temporary id, then learns a derived channel
		// id while it is still retained in tempChannels. Either id can scope the
		// peer's cancellation, but only the owning peer may remove the lifecycle.
		const exactTemp = this.tempChannels.get(channelIdHex);
		if (exactTemp) {
			if (this.removeCurrentTempChannel(peerPubkey, exactTemp)) {
				this.releaseErroredTempV2Pledges(exactTemp);
			}
		} else {
			const derivedTemp = this.findChannelByChannelIdInTemp(msg.channelId);
			if (derivedTemp) {
				if (this.removeCurrentTempChannel(peerPubkey, derivedTemp)) {
					this.releaseErroredTempV2Pledges(derivedTemp);
				}
			}
		}

		// BOLT 1: an error referencing a specific channel means fail that
		// channel, provided it belongs to the sender: a peer must not be able to
		// fail another peer's channel by quoting its id. While a tx_abort
		// exchange for a forgotten splice is pending, the peer's error is part
		// of that dance (CLN's channeld errors/restarts around it) — failing the
		// channel here would kill it right before it recovers.
		let channel = this.channels.get(channelIdHex);
		let ownerKeyHex = channelIdHex;
		if (!channel) {
			// A refusal of funding_created quotes the TEMPORARY id (the only id
			// that message carries), but with real queued transport it lands
			// after createFunding promoted the opener to its permanent id, so
			// the direct lookup misses and the error was silently dropped: the
			// channel sat in SENT_FUNDING_CREATED forever, renewing its funding
			// pledges every block (issue #412). Resolve the temporary id
			// against the promoted registrations too; ownership is still
			// checked under the key the channel is actually registered by.
			for (const [idHex, candidate] of this.channels) {
				if (candidate.getTemporaryChannelId().equals(msg.channelId)) {
					channel = candidate;
					ownerKeyHex = idHex;
					break;
				}
			}
		}
		const senderOwnsIt = this.channelPeers.get(ownerKeyHex) === peerPubkey;
		const inAbortDance = channel?.isSpliceAbortPending() ?? false;
		if (channel && senderOwnsIt && !inAbortDance) {
			this.failChannelByError(channel, `Remote error: ${errorText}`);
		}

		this.emit('error', msg.channelId, `Remote error: ${errorText}`);
	}

	/**
	 * Fail a channel per BOLT 1 error handling: mark it ERRORED, persist, and
	 * hand the on-chain close to the node via channel:errored. ERRORED alone
	 * would leave resolution to the peer's broadcast, which may never come
	 * (LND's ErrRecoveryError explicitly waits for us to close). The node
	 * drives the actual force-close: it owns the sweep script and fee
	 * estimate, and it skips dataLossDetected channels.
	 */
	private failChannelByError(channel: Channel, reason: string): void {
		if (!channel.markErrored()) return;
		const channelId = channel.getChannelId() ?? channel.getTemporaryChannelId();
		// A channel with no resolvable peer has nothing to write: the peer is
		// half of the channel_state mutation. The listener used to discover
		// that for itself and return; the resolution simply moved here.
		const peerPubkey = this.findPeerForChannel(channel);
		if (peerPubkey) {
			this.emit('channel:persist', {
				channel,
				peerPubkey,
				channelId
			} as IChannelPersistEvent);
		}
		this.emit('channel:errored', channelId, reason);
	}

	private handleWarningMsg(_peerPubkey: string, payload: Buffer): void {
		// BOLT 1 warning shares the error wire format (channel_id ++ data). A
		// warning is informational — the peer keeps the connection/channel alive —
		// but the text is often the only clue to a protocol disagreement (CLN
		// reports e.g. "Splice feerate_perkw is too low" this way), so surface it.
		const msg = decodeErrorMessage(payload);
		const warningText = msg.data.toString('utf8');
		this.emit('error', msg.channelId, `Remote warning: ${warningText}`);
	}

	private findTempChannel(channelId: Buffer): Channel | undefined {
		return this.tempChannels.get(channelId.toString('hex'));
	}

	// ─────────────── Helpers ───────────────

	private findPeerForChannel(channel: Channel): string | undefined {
		// Check permanent map first
		const channelId = channel.getChannelId();
		if (channelId) {
			const idHex = channelId.toString('hex');
			if (this.channels.get(idHex) === channel) {
				const peer = this.channelPeers.get(idHex);
				if (peer) return peer;
			}
		}
		// Check temp map
		const tempId = channel.getTemporaryChannelId().toString('hex');
		if (this.tempChannels.get(tempId) !== channel) return undefined;
		return this.channelPeers.get(tempId);
	}

	private findChannelByChannelId(channelId: Buffer): Channel | undefined {
		return this.channels.get(channelId.toString('hex'));
	}

	private findChannelByChannelIdInTemp(channelId: Buffer): Channel | undefined {
		for (const channel of this.tempChannels.values()) {
			const cid = channel.getChannelId();
			if (cid && cid.equals(channelId)) {
				return channel;
			}
		}
		return undefined;
	}

	/** Whether any channel lifecycle or owner binding already uses this id. */
	private channelIdInUse(idHex: string): boolean {
		return (
			this.channels.has(idHex) ||
			this.tempChannels.has(idHex) ||
			this.findChannelByChannelIdInTemp(Buffer.from(idHex, 'hex')) !==
				undefined ||
			this.channelPeers.has(idHex) ||
			this.channelIdReservations.has(idHex)
		);
	}

	/** Whether this exact lifecycle may claim an id without replacing another. */
	private channelIdAvailableForLifecycle(
		idHex: string,
		peerPubkey: string,
		channel: Channel
	): boolean {
		const permanent = this.channels.get(idHex);
		const temporary = this.tempChannels.get(idHex);
		const derivedTemporary = this.findChannelByChannelIdInTemp(
			Buffer.from(idHex, 'hex')
		);
		const reservation = this.channelIdReservations.get(idHex);
		if (permanent && permanent !== channel) return false;
		if (temporary && temporary !== channel) return false;
		if (derivedTemporary && derivedTemporary !== channel) return false;
		if (reservation && reservation !== channel) return false;
		const owner = this.channelPeers.get(idHex);
		if (owner === undefined) return true;
		if (owner !== peerPubkey) return false;
		return permanent === channel || temporary === channel;
	}

	/** Promote a channel while preserving any reentrant replacement lifecycle. */
	private promoteChannelLifecycle(
		peerPubkey: string,
		channel: Channel
	): boolean {
		const channelId = channel.getChannelId();
		if (!channelId) return false;
		const permanentId = channelId.toString('hex');
		const tempId = channel.getTemporaryChannelId().toString('hex');
		const ownsPermanent =
			this.channels.get(permanentId) === channel &&
			this.channelPeers.get(permanentId) === peerPubkey;
		const ownsTemporary =
			this.tempChannels.get(tempId) === channel &&
			this.channelPeers.get(tempId) === peerPubkey;
		if (!ownsPermanent && !ownsTemporary) return false;
		if (
			!this.channelIdAvailableForLifecycle(permanentId, peerPubkey, channel)
		) {
			return false;
		}

		this.channels.set(permanentId, channel);
		this.channelPeers.set(permanentId, peerPubkey);
		if (
			this.tempChannels.get(tempId) === channel &&
			this.channelPeers.get(tempId) === peerPubkey
		) {
			this.tempChannels.delete(tempId);
			if (tempId !== permanentId) this.channelPeers.delete(tempId);
		}
		return true;
	}

	/**
	 * Apply an ERROR action's cleanup disposition. See IErrorAction.cleanup.
	 *
	 * Returns whether anything was removed, which is what gates the v2 pledge
	 * release and the contained re-emit at the end of processActions.
	 */
	private cleanupForError(
		peerPubkey: string,
		channel: Channel,
		cleanup: IErrorAction['cleanup']
	): boolean {
		if (cleanup === 'none') return false;
		if (cleanup === 'lifecycle') {
			return this.removeCurrentChannelLifecycle(peerPubkey, channel);
		}
		return this.removeCurrentTempChannel(peerPubkey, channel);
	}

	/** Remove a temporary channel only when this exact lifecycle still owns it. */
	private removeCurrentTempChannel(
		peerPubkey: string,
		channel: Channel
	): boolean {
		const tempId = channel.getTemporaryChannelId().toString('hex');
		if (
			this.tempChannels.get(tempId) !== channel ||
			this.channelPeers.get(tempId) !== peerPubkey
		) {
			return false;
		}
		this.tempChannels.delete(tempId);
		this.channelPeers.delete(tempId);
		return true;
	}

	/** Remove this exact peer and channel lifecycle from every active map. */
	private removeCurrentChannelLifecycle(
		peerPubkey: string,
		channel: Channel
	): boolean {
		let removed = false;
		const channelId = channel.getChannelId()?.toString('hex');
		if (
			channelId &&
			this.channels.get(channelId) === channel &&
			this.channelPeers.get(channelId) === peerPubkey
		) {
			this.channels.delete(channelId);
			this.channelPeers.delete(channelId);
			removed = true;
		}
		const tempId = channel.getTemporaryChannelId().toString('hex');
		if (
			this.tempChannels.get(tempId) === channel &&
			this.channelPeers.get(tempId) === peerPubkey
		) {
			this.tempChannels.delete(tempId);
			this.channelPeers.delete(tempId);
			removed = true;
		} else if (
			removed &&
			!this.tempChannels.has(tempId) &&
			this.channelPeers.get(tempId) === peerPubkey
		) {
			// Promotion can leave the temporary owner binding behind after the
			// channel itself moved to the permanent map.
			this.channelPeers.delete(tempId);
		}
		return removed;
	}

	/**
	 * Release the wallet pledges of a conclusively dead v2 open (issue #311).
	 * The channel getter reports outpoints only for an abandoned open with
	 * nothing anyone could broadcast (getReleasableV2PledgeOutpoints), so
	 * every call site fails safe; a channel the node's channel:abandoned
	 * listener re-restored (resumable RBF row) is skipped. Best effort by
	 * design: the pledge TTL remains the backstop.
	 */
	private releaseAbandonedV2Pledges(channel: Channel): void {
		if (!this.fundingProvider?.releaseInputPledges) return;
		if (this._fundingPledgesReleased.has(channel)) return;
		const outpoints = channel.getReleasableV2PledgeOutpoints();
		if (outpoints.length === 0) return;
		const id = channel.getChannelId() ?? channel.getTemporaryChannelId();
		const idHex = id?.toString('hex');
		if (idHex && (this.channels.has(idHex) || this.tempChannels.has(idHex))) {
			return;
		}
		// A durable row a restart could restore keeps its pledges: releasing
		// here would let the wallet double-spend the input of an open that
		// resumes after a restart. The TTL remains the backstop.
		if (id && this.config.hasResumableChannelRow?.(id) === true) return;
		this._fundingPledgesReleased.add(channel);
		releaseInputPledgesBestEffort(this.fundingProvider, outpoints);
	}

	/**
	 * A v2 temp open just deleted because of a fatal BOLT 1 error: mark it
	 * ERRORED (consistent with failChannelByError; also what lets the
	 * abandoned-v2 getter answer) and release its funding pledges
	 * (issue #311). v1 opens are handled by the sibling below.
	 */
	private releaseErroredTempV2Pledges(channel: Channel): void {
		if (channel.getFullState().fundingVersion !== 2) return;
		channel.markErrored();
		this.releaseAbandonedV2Pledges(channel);
	}

	/**
	 * Release the wallet pledges behind a v1 funding tx that was signed but
	 * whose broadcast was provably never authorized (issue #412).
	 * SENT_FUNDING_CREATED is the proof: handleFundingSigned moves to
	 * AWAITING_FUNDING_CONFIRMED before it can emit
	 * AUTHORIZE_FUNDING_BROADCAST, and the node never reauthorizes a
	 * SENT_FUNDING_CREATED channel. Any later state may have been broadcast
	 * and keeps its pledges; the node's entry-retirement sweep backstops
	 * those. Deliberately does NOT markErrored: nothing is on chain, and a
	 * v1 open dropped this way keeps its historical state.
	 */
	private releaseRefusedV1FundingPledges(channel: Channel): void {
		if (!this.fundingProvider?.releaseInputPledges) return;
		if (this._fundingPledgesReleased.has(channel)) return;
		const state = channel.getFullState();
		if (state.fundingVersion === 2) return;
		if (state.state !== ChannelState.SENT_FUNDING_CREATED) return;
		if (!state.pendingFundingTxHex) return;
		const id = channel.getChannelId() ?? channel.getTemporaryChannelId();
		const idHex = id?.toString('hex');
		if (idHex && (this.channels.has(idHex) || this.tempChannels.has(idHex))) {
			return;
		}
		if (id && this.config.hasResumableChannelRow?.(id) === true) return;
		const outpoints = txInputOutpoints(state.pendingFundingTxHex);
		if (outpoints.length === 0) return;
		this._fundingPledgesReleased.add(channel);
		releaseInputPledgesBestEffort(this.fundingProvider, outpoints);
	}

	/**
	 * Release the pledges of a wallet selection that resolved after its open
	 * died (issue #311). The inputs were selected and frozen but never
	 * registered on any channel, never contributed and never signed, so the
	 * release is unconditionally safe.
	 */
	private releaseStaleSelectionPledges(inputs: ISpliceWalletInput[]): void {
		if (!this.fundingProvider?.releaseInputPledges || inputs.length === 0) {
			return;
		}
		const outpoints: Array<{ txid: string; vout: number }> = [];
		for (const input of inputs) {
			try {
				outpoints.push({
					txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
					vout: input.prevOutputIndex
				});
			} catch {
				// Unreadable prevTx cannot name a pledge; the TTL covers it.
			}
		}
		if (outpoints.length === 0) return;
		releaseInputPledgesBestEffort(this.fundingProvider, outpoints);
	}

	/**
	 * Release the pledges of wallet inputs a channel selected to raise its v2
	 * funding contribution, where the RBF that would have spent them never
	 * took effect (refused, disconnected, or rolled back). The channel only
	 * reports inputs no attempt of its own spends, so unlike the abandoned-open
	 * release this is safe while the channel is very much alive. Best effort:
	 * the wallet's pledge TTL is the backstop for windows no drain reaches.
	 */
	private releaseDanglingV2Pledges(channel: Channel): void {
		if (!this.fundingProvider?.releaseInputPledges) return;
		const outpoints = channel.takeDanglingV2TopUpPledgeOutpoints();
		if (outpoints.length === 0) return;
		releaseInputPledgesBestEffort(this.fundingProvider, outpoints);
	}

	/**
	 * Keep the per-channel quiescence watchdog in step with the channel's
	 * quiescence state (BOLT 2 60-second disconnect). Runs on every action
	 * batch, INCLUDING empty ones: quiescence-exiting channel methods
	 * (abortSplice, exitQuiescence) can return no actions. Terminal exits that
	 * bypass processActions entirely (markErrored, force close) are covered by
	 * the fire-time re-check, which emits 'quiescence:ended' instead of
	 * timing out when the session is already over.
	 */
	private _syncQuiescenceWatchdog(channel: Channel): void {
		// Tolerate partial channel doubles in tests and recovery shims.
		if (typeof channel.isQuiescing !== 'function') return;
		const channelIdHex = channel.getChannelId()?.toString('hex');
		if (!channelIdHex) return;
		const timer = this.quiescenceTimers.get(channelIdHex);
		if (channel.isQuiescing()) {
			if (timer) return;
			const t = setTimeout(() => {
				this.quiescenceTimers.delete(channelIdHex);
				this._onQuiescenceTimeout(channelIdHex);
			}, this.config.quiescenceTimeoutMs ?? DEFAULT_QUIESCENCE_TIMEOUT_MS);
			if (typeof t.unref === 'function') t.unref();
			this.quiescenceTimers.set(channelIdHex, t);
			return;
		}
		if (timer) {
			clearTimeout(timer);
			this.quiescenceTimers.delete(channelIdHex);
			this.emit('quiescence:ended', channelIdHex);
			// Deferred (issue 430): this sync point runs inside processActions,
			// and the drained settles start dispatches of their own.
			setImmediate(() => {
				this._drainDeferredSettles(channelIdHex);
			});
		}
	}

	/** Queue an HTLC settle for after quiescence; true when it was deferred. */
	private _deferSettleIfQuiescing(
		channelIdHex: string,
		channel: Channel,
		op:
			| { kind: 'fulfill'; htlcId: bigint; preimage: Buffer }
			| {
					kind: 'fail';
					htlcId: bigint;
					reason: Buffer;
					direction: HtlcDirection;
			  }
			| {
					kind: 'failMalformed';
					htlcId: bigint;
					sha256OfOnion: Buffer;
					failureCode: number;
			  }
	): boolean {
		if (typeof channel.isQuiescing !== 'function' || !channel.isQuiescing()) {
			return false;
		}
		const list = this.pendingQuiescentSettles.get(channelIdHex) ?? [];
		list.push(op);
		this.pendingQuiescentSettles.set(channelIdHex, list);
		return true;
	}

	/**
	 * Apply HTLC settles deferred while their channel was quiescing. Entries
	 * are removed from the map BEFORE replay: the replayed call re-defers if
	 * quiescence somehow resumed, and the per-block retry must never race the
	 * quiescence-ended drain into a double apply. Held (not consumed) while
	 * the channel cannot carry updates (AWAITING_REESTABLISH); purged on
	 * terminal states, where the HTLCs resolve on-chain instead.
	 */
	private _drainDeferredSettles(channelIdHex: string): void {
		const list = this.pendingQuiescentSettles.get(channelIdHex);
		if (!list?.length) return;
		const channel = this.channels.get(channelIdHex);
		if (!channel) {
			this.pendingQuiescentSettles.delete(channelIdHex);
			return;
		}
		const state = channel.getState();
		if (
			state === ChannelState.ERRORED ||
			state === ChannelState.CLOSED ||
			state === ChannelState.FORCE_CLOSED
		) {
			this.pendingQuiescentSettles.delete(channelIdHex);
			return;
		}
		if (channel.isQuiescing() || !channel.canSettleHtlcs()) return;
		this.pendingQuiescentSettles.delete(channelIdHex);
		const channelId = Buffer.from(channelIdHex, 'hex');
		for (const op of list) {
			if (op.kind === 'fulfill') {
				this.fulfillHtlc(channelId, op.htlcId, op.preimage);
			} else if (op.kind === 'fail') {
				this.failHtlc(channelId, op.htlcId, op.reason, op.direction);
			} else {
				this.failMalformedHtlc(
					channelId,
					op.htlcId,
					op.sha256OfOnion,
					op.failureCode
				);
			}
		}
	}

	private _onQuiescenceTimeout(channelIdHex: string): void {
		const channel = this.channels.get(channelIdHex);
		if (!channel) return;
		if (!channel.isQuiescing()) {
			// The session ended through a path with no watchdog sync point;
			// release anything parked on it.
			this.emit('quiescence:ended', channelIdHex);
			return;
		}
		// BOLT 2 disconnects "if the HTLCs are pending": an idle operator
		// quiescence with no HTLC entries at all may stand. Re-arm, since a
		// crossing add could still land while the session continues.
		if (channel.getFullState().htlcs.size === 0) {
			this._syncQuiescenceWatchdog(channel);
			return;
		}
		const peerPubkey = this.channelPeers.get(channelIdHex);
		if (peerPubkey === undefined) return;
		this.emit('quiescence:timeout', channelIdHex, peerPubkey);
	}

	private processActions(
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[],
		progress?: IActionDispatchProgress
	): void {
		this._syncQuiescenceWatchdog(channel);
		if (actions.length === 0) return;
		const dispatchProgress = progress ?? newDispatchProgress();
		const errorIndex = actions.findIndex(
			(action) => action.type === ChannelActionType.ERROR
		);
		const errorAction = errorIndex >= 0 ? actions[errorIndex] : undefined;
		try {
			this.processActionsUnchecked(
				peerPubkey,
				channel,
				actions,
				dispatchProgress
			);
		} finally {
			// Cleanup is allowed once the local error ran, or once its cancellation
			// reached the transport boundary.
			if (
				errorAction?.type === ChannelActionType.ERROR &&
				(dispatchProgress.completedIndex >= errorIndex ||
					dispatchProgress.attemptedMessageTypes.has(MessageType.ERROR) ||
					dispatchProgress.attemptedMessageTypes.has(MessageType.TX_ABORT)) &&
				// Honours the same disposition as the dispatch arm: a guard that
				// refuses in order to PRESERVE a live negotiation must not have it
				// deleted here instead when a listener throws mid-batch.
				this.cleanupForError(peerPubkey, channel, errorAction.cleanup)
			) {
				// Same pledge-release hooks as the dispatch arm. A listener that
				// throws mid-batch (a failed wire send, say) lands here instead,
				// and this cleanup deregisters the channel, so no disconnect sweep
				// will ever find it again: skipping the release here would strand
				// the wallet inputs until their TTL (issues #311/#412).
				this.releaseErroredTempV2Pledges(channel);
				this.releaseRefusedV1FundingPledges(channel);
				this.emitContained(
					'error',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					errorAction.message
				);
			}
		}
	}

	private processActionsUnchecked(
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[],
		progress: IActionDispatchProgress
	): void {
		// Keep the channel's node-id ordering current (BOLT 2 interactive-tx
		// tx_signatures tie-break): the channel itself never learns node ids.
		if (this.config.nodePrivateKey) {
			if (!this.localNodeIdCache) {
				this.localNodeIdCache = getPublicKey(this.config.nodePrivateKey);
			}
			channel.setLocalNodeIdLower(
				Buffer.compare(this.localNodeIdCache, Buffer.from(peerPubkey, 'hex')) <
					0
			);
		}

		// ── Structural persist-before-send (Recovery Protocol 5.1/5.2) ──
		// Every retransmittable SEND_MESSAGE that FOLLOWS the batch's
		// PERSIST_STATE is authorized by the state that persist writes, so its
		// exact wire bytes are handed to the persist listener and committed in
		// the SAME transaction. Ordering safety no longer rests on each handler
		// happening to place PERSIST_STATE before its sends: a send whose
		// justifying state failed to commit is withheld outright.
		const batchChannelId = channel.getChannelId();
		const persistIndex = actions.findIndex(
			(a) => a.type === ChannelActionType.PERSIST_STATE
		);
		const persistRequest: IChannelPersistRequest | null =
			persistIndex >= 0 && batchChannelId
				? {
						outbound: actions
							.slice(persistIndex + 1)
							.filter(
								(a): a is ISendMessageAction =>
									a.type === ChannelActionType.SEND_MESSAGE &&
									// A replay is already in the outbox from its original
									// send; storing it again on every reconnect would churn
									// the table without making anything more recoverable.
									a.replay !== true &&
									RETRANSMITTABLE_MESSAGE_TYPES.has(a.messageType)
							)
							.map((a) => ({
								peerId: peerPubkey,
								channelId: batchChannelId.toString('hex'),
								messageType: a.messageType,
								wireMessage: a.payload,
								disposition: 'pending_send' as const
							})),
						committed: true,
						outboxIds: []
				  }
				: null;
		// Fold a staged revoke supersede into this batch's persist request so
		// the row deletions ride the same transaction as the channel state.
		// Cleared unconditionally: it was staged for exactly this batch, and a
		// batch it cannot ride with must not delete anything (rows are only
		// ever retired by a transition that actually committed).
		const pendingSupersede = this._pendingOutboxSupersede;
		this._pendingOutboxSupersede = null;
		if (
			pendingSupersede &&
			persistRequest &&
			batchChannelId &&
			pendingSupersede.channelIdHex === batchChannelId.toString('hex')
		) {
			persistRequest.supersede = {
				messageTypes: pendingSupersede.messageTypes
			};
		}
		// Set once a persist fails: nothing that persist authorized may go out.
		let sendsBlocked = false;

		// ── Quorum durability barrier (Recovery Protocol 5.8, Phase 6) ──
		// Outside quorum mode `shouldHold` is a constant false and the whole
		// batch dispatches synchronously exactly as before. Inside it, a batch
		// carrying a barrier-class message whose frame is not yet quorum
		// durable stops after its persist and the REMAINDER of the action list
		// is held, so the peer sees nothing the guardians do not already hold.
		const channelIdHex = batchChannelId?.toString('hex') ?? null;
		let heldFrom = -1;

		// ── The barrier's structural invariant (Recovery 5.8) ──
		// A barrier-class message is only ever released against the frame that
		// authorized it, and the ONLY thing that names that frame is this
		// batch's own PERSIST_STATE. A batch that puts such a message on the
		// wire with no persist ahead of it is therefore unreleasable by
		// construction: no receipt exists that could cover it, so the honest
		// answer is to send nothing. Enforced HERE, before a single action
		// runs, because the release path is asked about frames rather than
		// about batches and would have to answer "no frame, nothing to wait
		// for", which reads as permission. Every producer in this codebase
		// leads with its persist, so a violation is a producer bug, and the
		// safe response to a producer bug on a fund-critical path is silence.
		if (channelIdHex && this._lacksFrameAttribution(actions, persistIndex)) {
			this._noteSendsHeld(progress, actions, 0);
			this._refuseUnattributed(channelIdHex, peerPubkey, channel, actions);
			return;
		}

		// A channel that is ALREADY holding messages holds this batch too, and
		// the check has to happen here rather than at the PERSIST_STATE action,
		// because a batch with no persist never reaches that case. Those exist
		// and are not exotic: initiateShutdown, the closing_signed rounds, stfu
		// and createReestablish all dispatch persist-less arrays. Without this
		// they would overtake a parked revoke_and_ack and reorder the channel's
		// wire stream. A batch WITH a persist still runs up to and including it
		// (that state must reach disk) and is held from the action after.
		if (
			channelIdHex &&
			persistIndex < 0 &&
			this.barrierQueues.has(channelIdHex)
		) {
			this._noteSendsHeld(progress, actions, 0);
			this._holdBatch(channelIdHex, peerPubkey, channel, {
				actions,
				from: 0,
				frameSequence: null,
				requiresDurability: this._carriesBarrierMessage(actions, 0),
				outboxIds: []
			});
			return;
		}

		this.emitContained('transition:begin', channelIdHex);
		try {
			heldFrom = this._dispatchActions(
				peerPubkey,
				channel,
				actions,
				persistRequest,
				() => sendsBlocked,
				(blocked: boolean) => {
					sendsBlocked = blocked;
					if (blocked) progress.sendsWithheld = true;
				},
				0,
				false,
				(): boolean =>
					this._shouldHoldBatch(
						channelIdHex,
						actions,
						persistIndex,
						persistRequest
					),
				progress
			);
			if (
				heldFrom < 0 &&
				!sendsBlocked &&
				persistRequest &&
				persistRequest.outboxIds.length
			) {
				this.emit('outbox:sent', persistRequest.outboxIds);
			}
		} finally {
			this.emitContained('transition:end', channelIdHex);
		}
		if (heldFrom >= 0 && channelIdHex) {
			this._noteSendsHeld(progress, actions, heldFrom);
			this._holdBatch(channelIdHex, peerPubkey, channel, {
				actions,
				from: heldFrom,
				frameSequence: persistRequest?.frameSequence ?? null,
				requiresDurability: this._carriesBarrierMessage(actions, heldFrom),
				outboxIds: persistRequest ? [...persistRequest.outboxIds] : []
			});
		}
		// A failed persist withheld this batch's sends. The messages are gone
		// from this connection (nothing re-queues them), so the ONLY way they
		// reach the peer is the reestablish path after a reconnect, which also
		// retries the persist. Surface that so the node can force the
		// disconnect instead of deadlocking a live connection on a peer
		// timeout we do not control.
		if (sendsBlocked) {
			progress.sendsWithheld = true;
			this.emit('transition:blocked', peerPubkey, batchChannelId);
		}
		// Hand back the coins a rollback in this batch unregistered — but only
		// once the batch committed. A rollback whose persist failed is undone
		// by the live resync, which restores the durable replacement from
		// disk; releasing its inputs first would unfreeze coins that restored
		// record still spends, and nothing re-pledges an unsigned attempt. The
		// stash is left intact so the batch that does commit releases them.
		// Cheap when nothing is staged, and this is the one path every
		// dispatch-driven rollback funnels through.
		if (!sendsBlocked && heldFrom < 0) {
			this.releaseDanglingV2Pledges(channel);
		}
	}

	/**
	 * Run a batch's actions.
	 *
	 * Returns the index the run STOPPED at when a quorum barrier held the rest
	 * of the batch, or -1 when it ran to completion. Holding a suffix rather
	 * than only the sends is deliberate: the loop interleaves sends with
	 * broadcasts, force closes and the re-entrant HTLC emits in one order, and
	 * releasing any of those while their message waits would invert the batch.
	 * A splice's tx_signatures and the BROADCAST_TX of the transaction it
	 * signs sit in the same array, so deferring the send alone would put the
	 * transaction on the network before the peer saw the message authorizing
	 * it.
	 *
	 * `startIndex` and `persistAlreadySeen` exist so a held suffix resumes
	 * through this same code, keeping one implementation of every action's
	 * meaning and preserving the one-persist-per-batch rule across the wait.
	 */
	private _dispatchActions(
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[],
		persistRequest: IChannelPersistRequest | null,
		sendsBlocked: () => boolean,
		setSendsBlocked: (blocked: boolean) => void,
		startIndex = 0,
		persistAlreadySeen = false,
		shouldHold?: () => boolean,
		progress?: IActionDispatchProgress
	): number {
		let persistSeen = persistAlreadySeen;
		for (let index = startIndex; index < actions.length; index++) {
			// How far the run got. A re-entrant handler can throw out of this
			// loop, and the actions AFTER the thrower are then untouched: their
			// committed edge-triggered effects are still owed, so the caller
			// needs to know where to resume them from.
			if (progress) progress.index = index;
			const action = actions[index];
			switch (action.type) {
				case ChannelActionType.SEND_MESSAGE:
					// A message the failed persist authorized must not reach the
					// peer: the state that justifies it is not on disk.
					if (persistSeen && sendsBlocked()) {
						if (progress) progress.sendsWithheld = true;
						break;
					}
					progress?.attemptedMessageTypes.add(action.messageType);
					this.sendMessage(peerPubkey, action.messageType, action.payload);
					// BOLT 1: the SENDER of an error must fail the channel too. A
					// channel that just emitted a wire error and sits ERRORED (peer
					// protocol violation, DLP fell-behind) gets its close driven by
					// the node, which skips the broadcast when dataLossDetected
					// forbids it.
					if (
						action.messageType === MessageType.ERROR &&
						channel.getState() === ChannelState.ERRORED
					) {
						this.emit(
							'channel:errored',
							channel.getChannelId() ?? channel.getTemporaryChannelId(),
							'local wire error failed the channel'
						);
					}
					break;
				case ChannelActionType.CHANNEL_READY:
					this.emit('channel:ready', action.channelId);
					break;
				case ChannelActionType.CHANNEL_CLOSED:
					this.emit('channel:closed', action.channelId);
					break;
				case ChannelActionType.ERROR: {
					// A channel that failed before funding has no permanent id yet, so
					// fall back to the temporary one: without it the error carries a
					// null channelId and cannot be tied back to the open it belongs to.
					if (this.cleanupForError(peerPubkey, channel, action.cleanup)) {
						// A validation error just ended a tracked v2 open (an
						// invalid peer contribution, a failed audit): its
						// funding pledges release with it (issue #311). Same
						// for a v1 open refused before its broadcast was ever
						// authorized (issue #412).
						this.releaseErroredTempV2Pledges(channel);
						this.releaseRefusedV1FundingPledges(channel);
					}
					this.emit(
						'error',
						channel.getChannelId() ?? channel.getTemporaryChannelId(),
						action.message
					);
					break;
				}
				case ChannelActionType.HTLC_FORWARDED:
					this.emit(
						'htlc:forwarded',
						channel.getChannelId(),
						action.htlcId,
						action.amountMsat,
						action.paymentHash
					);
					break;
				case ChannelActionType.HTLC_FULFILLED:
					this.emit(
						'htlc:fulfilled',
						channel.getChannelId(),
						action.htlcId,
						action.paymentPreimage
					);
					break;
				case ChannelActionType.HTLC_FAILED:
					this.emit(
						'htlc:failed',
						channel.getChannelId(),
						action.htlcId,
						action.reason
					);
					break;
				case ChannelActionType.WATCH_FUNDING:
					this.emit(
						'watch:funding',
						action.fundingTxid,
						action.fundingOutputIndex,
						action.minimumDepth
					);
					// A splice re-watches a NEW funding outpoint on an existing
					// channel; only a first-time funding watch means "opening".
					// ERRORED is excluded too: a splice tx_signatures wire
					// failure retains the splice-outpoint watch in the same
					// batch that moved the channel to ERRORED, and no first-time
					// funding watch is ever emitted by an ERRORED channel.
					if (
						channel.getState() !== ChannelState.SPLICING &&
						channel.getState() !== ChannelState.ERRORED
					) {
						this.emit(
							'channel:opening',
							channel.getChannelId() || channel.getTemporaryChannelId(),
							action.fundingTxid
						);
					}
					break;
				case ChannelActionType.WATCH_PRESPLICE_SPEND:
					// Ungated, for the same reasons WATCH_FUNDING is: it puts no
					// bytes on the wire, changes nothing on chain, and is
					// idempotent per outpoint. On a refused persist the right
					// disposition is still the outpoint watched and the
					// transaction not created. No 'channel:opening' companion
					// either - this action moves nothing and describes no new
					// funding.
					this.emit('watch:presplice-spend', action.channelId);
					break;
				case ChannelActionType.AUTHORIZE_FUNDING_BROADCAST:
					// Same guard and the same reason as BROADCAST_TX below: a
					// funding transaction whose channel state never reached
					// disk is a 2-of-2 no restored node can enumerate.
					if (persistSeen && sendsBlocked()) {
						break;
					}
					this.emit('funding:authorized', action.fundingTxid);
					break;
				case ChannelActionType.BROADCAST_TX:
					// A transaction the failed persist authorized must not reach
					// the network either: a splice or funding tx broadcast whose
					// justifying state never hit disk is exactly the "network saw
					// a tx we have no record of" crash the persist-first comments
					// at the producers promise to prevent.
					if (persistSeen && sendsBlocked()) {
						break;
					}
					this.emit('broadcast:tx', action.tx);
					break;
				case ChannelActionType.FORCE_CLOSE:
					if (persistSeen && sendsBlocked()) {
						break;
					}
					this.emit('force:close', action.channelId, action.commitmentTx);
					break;
				case ChannelActionType.WATCH_OUTPUT:
					this.emit('watch:output', action.txid, action.outputIndex);
					break;
				case ChannelActionType.PREIMAGE_LEARNED:
					this.emit('preimage:learned', action.paymentHash, action.preimage);
					break;
				case ChannelActionType.CHANNEL_FULLY_RESOLVED:
					this.emit('channel:resolved', action.channelId);
					break;
				case ChannelActionType.TX_SIGNATURES_NEEDED:
					// A failed persist withholds this batch's earlier sends (our
					// own commitment_signed can be among them). A listener
					// answering this notification dispatches tx_signatures in a
					// FRESH batch no failed-persist marker withholds, putting
					// witnesses on the wire before a commitment the peer never
					// received, which the peer rejects. Suppress instead; the
					// reconnect that follows re-arms the reminder
					// (markForReestablish).
					if (persistSeen && sendsBlocked()) {
						break;
					}
					this.emit(
						'channel:txsigs-needed',
						action.channelId,
						action.fundingTxid,
						action.fundingOutputIndex,
						action.inputIndices,
						action.externalInputIndices
					);
					break;
				case ChannelActionType.SPLICE_TX_SIGNATURES_NEEDED:
					// Suppressed on a failed persist for the same reason as the
					// v2 signal above: answering it (provideSpliceExternalWitness)
					// releases tx_signatures in a FRESH batch no failed-persist
					// marker withholds, ahead of a splice commitment_signed the
					// peer never received. The reconnect re-arms the reminder
					// (markForReestablish).
					if (persistSeen && sendsBlocked()) {
						break;
					}
					this.emit(
						'channel:splice-txsigs-needed',
						action.channelId,
						action.spliceTxid,
						action.newFundingOutputIndex,
						action.externalInputIndices
					);
					break;
				case ChannelActionType.ANNOUNCEMENT_READY:
					this.emit(
						'announcement:ready',
						action.channelId,
						action.channelAnnouncement,
						action.channelUpdate
					);
					break;
				case ChannelActionType.PERSIST_STATE:
					// One commit per batch. Channel methods mutate state fully
					// while BUILDING the action array, so every PERSIST_STATE in
					// a batch would write the identical state; batches composed
					// from helpers that each lead with their own persist (the v2
					// open and splice signing flows) used to re-commit the same
					// outbound list once per marker, duplicating its outbox rows.
					if (persistSeen) {
						break;
					}
					persistSeen = true;
					this.emit('channel:persist', {
						channel,
						peerPubkey,
						channelId:
							channel.getChannelId() ?? channel.getTemporaryChannelId(),
						request: persistRequest ?? undefined
					} as IChannelPersistEvent);
					// No listener (or no storage) leaves committed true, which is
					// the pre-outbox behavior for a node that persists nothing.
					if (persistRequest && !persistRequest.committed) {
						setSendsBlocked(true);
						break;
					}
					// The frame this transition landed in is only known now, so
					// the barrier question is asked here and nowhere else. A
					// failed persist takes precedence: there is nothing durable
					// to wait for.
					if (shouldHold?.()) {
						if (progress) progress.completedIndex = index;
						return index + 1;
					}
					break;
				case ChannelActionType.SPLICE_COMPLETE:
					this.emit('splice:complete', channel.getChannelId());
					break;
				case ChannelActionType.SPLICE_ABORTED:
					// The channel's newly-aborted signal (issue #581): the ONE
					// source of truth for splice:aborted, covering local
					// aborts (which settle before the echo), peer aborts,
					// disconnected aborts that never pass through NORMAL, and
					// reestablish unwinds, exactly once per attempt.
					this.emitContained('splice:aborted', action.channelId, action.reason);
					break;
			}
			if (progress) progress.completedIndex = index;
		}
		return -1;
	}

	// ─────────── Quorum durability barrier (Recovery 5.8, Phase 6) ───────────

	/**
	 * Should this batch's remainder be held behind the barrier?
	 *
	 * Two reasons, and the second is what preserves wire order. A batch is
	 * held when it carries a barrier-class message whose frame is not yet
	 * quorum durable; and a channel that is ALREADY holding messages holds
	 * everything after them too, barrier-class or not, because letting a later
	 * message overtake a held one would reorder the channel's wire stream.
	 */
	private _shouldHoldBatch(
		channelIdHex: string | null,
		actions: ChannelAction[],
		persistIndex: number,
		persistRequest: IChannelPersistRequest | null
	): boolean {
		const barrier = this.config.durabilityBarrier;
		if (!barrier || !barrier.enforcing || !channelIdHex) return false;
		if (this.barrierQueues.has(channelIdHex)) return true;
		if (!this._carriesBarrierMessage(actions, persistIndex + 1)) return false;
		return !barrier.isReleased(persistRequest?.frameSequence ?? null);
	}

	/**
	 * A namespace that can never advance again must not take on a new
	 * commitment it can never record.
	 *
	 * Only opening is refused. Every other irreversible step is barrier-class
	 * and now refuses immediately with its own reason; funding_created,
	 * funding_signed and channel_ready are not, so an open would otherwise run
	 * to completion into a namespace with no future. Closing keeps working in
	 * both forms, cooperative and forced, because it is the only exit an
	 * operator has left.
	 */
	private _namespaceCannotRecordANewChannel(): boolean {
		const barrier = this.config.durabilityBarrier;
		return barrier?.enforcing === true && barrier.namespaceLost === true;
	}

	private _assertNamespaceCanRecordANewChannel(): void {
		if (this._namespaceCannotRecordANewChannel()) {
			throw new Error(NAMESPACE_LOST_REFUSAL);
		}
	}

	/**
	 * Is this action a send the quorum barrier gates?
	 *
	 * Two sources, because the gated set is two things. Most of spec 5.8's rows
	 * are whole message TYPES that are irreversible wherever they appear. The
	 * data-loss declaration is not: `error` is also BOLT 1's ordinary
	 * protocol-violation message, so that row is carried by a mark the producer
	 * sets on the action it means.
	 */
	private _isBarrierClass(action: ChannelAction): boolean {
		// Gated without being a send. Putting a funding output on chain is
		// irreversible in exactly the sense the barrier is about: the network
		// cannot be asked to forget a transaction, and a restore below the
		// frame that FIRST records the channel comes back not knowing it
		// exists. The v1 funder has no transaction inside the channel to mark,
		// so its authorization is its own action; the splice and v2 paths
		// already build a BROADCAST_TX and carry a mark on it instead. The mark
		// is opt-in because a force close is a BROADCAST_TX too and must never
		// be refusable.
		if (action.type === ChannelActionType.AUTHORIZE_FUNDING_BROADCAST) {
			return true;
		}
		if (action.type === ChannelActionType.BROADCAST_TX) {
			return action.fundingCritical === true;
		}
		if (action.type !== ChannelActionType.SEND_MESSAGE) return false;
		return (
			action.durabilityCritical === true ||
			QUORUM_BARRIER_MESSAGE_TYPES.has(action.messageType)
		);
	}

	/**
	 * Note that a suffix the barrier parked (or dropped) still owes the wire.
	 *
	 * Only sends count. A held suffix carries broadcasts and internal emits too,
	 * but no peer is waiting on those, and a caller asking whether its message
	 * left is asking about the socket.
	 */
	private _noteSendsHeld(
		progress: IActionDispatchProgress,
		actions: ChannelAction[],
		from: number
	): void {
		for (let index = Math.max(from, 0); index < actions.length; index++) {
			if (actions[index].type === ChannelActionType.SEND_MESSAGE) {
				progress.sendsHeld = true;
				return;
			}
		}
	}

	/**
	 * Is a tx_signatures for this channel still parked behind the barrier?
	 *
	 * The witness entry points ask after their own dispatch, because a repeat
	 * delivery is a no-op at the channel: the record already says our
	 * tx_signatures were released, so the second call produces no actions and no
	 * progress of its own. Reading that as a clean dispatch would tell a caller
	 * holding an obligation to the input's owner that it was discharged by bytes
	 * still sitting in the queue, which a refused release then drops.
	 */
	private _txSignaturesStillHeld(channel: Channel): boolean {
		const channelIdHex = channel.getChannelId()?.toString('hex');
		if (!channelIdHex) return false;
		const queue = this.barrierQueues.get(channelIdHex);
		if (!queue) return false;
		return queue.batches.some((batch) =>
			batch.actions.some(
				(action, index) =>
					index >= batch.from &&
					action.type === ChannelActionType.SEND_MESSAGE &&
					action.messageType === MessageType.TX_SIGNATURES
			)
		);
	}

	/** Does the suffix from `from` put a message the barrier gates on the wire? */
	private _carriesBarrierMessage(
		actions: ChannelAction[],
		from: number
	): boolean {
		for (let index = Math.max(from, 0); index < actions.length; index++) {
			if (this._isBarrierClass(actions[index])) return true;
		}
		return false;
	}

	/**
	 * Does this batch send a barrier-class message that no persist authorizes?
	 *
	 * Only ever true in quorum mode, and only for a batch whose first
	 * barrier-class send has no PERSIST_STATE before it. `persistIndex > first`
	 * counts as well: a persist AFTER the send did not authorize that send.
	 */
	private _lacksFrameAttribution(
		actions: ChannelAction[],
		persistIndex: number
	): boolean {
		const barrier = this.config.durabilityBarrier;
		if (!barrier || !barrier.enforcing) return false;
		const first = actions.findIndex((action) => this._isBarrierClass(action));
		if (first < 0) return false;
		return persistIndex < 0 || persistIndex > first;
	}

	/**
	 * Refuse a batch whose barrier-class message no frame authorizes.
	 *
	 * Same disposition a timed-out barrier already has, for the same reason:
	 * the WIRE half is dropped, and the rest of the batch still runs, because a
	 * suffix also carries the edge-triggered internal effects of state that is
	 * already on disk (handleRevokeAndAck sets forwardEmitted while BUILDING
	 * its actions, so an HTLC_FORWARDED dropped outright would leave that HTLC
	 * unforwarded until its CLTV). `transition:frozen` then has the node
	 * disconnect, so the channel reconciles through channel_reestablish rather
	 * than leaving the peer waiting on a message that will never come.
	 */
	private _refuseUnattributed(
		channelIdHex: string,
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[]
	): void {
		this.runHeldSuffixWithoutSending(peerPubkey, channel, {
			actions,
			from: 0,
			frameSequence: null,
			requiresDurability: true,
			outboxIds: []
		});
		this.emit(
			'transition:frozen',
			peerPubkey,
			channelIdHex,
			'missing-frame',
			1
		);
		this.emit(
			'error',
			channel.getChannelId(),
			'durability barrier: a batch carrying a quorum-gated message has no ' +
				'PERSIST_STATE naming the frame that authorized it, so nothing was sent'
		);
	}

	/** Park a held suffix and arm its release. */
	private _holdBatch(
		channelIdHex: string,
		peerPubkey: string,
		channel: Channel,
		held: IHeldBatch
	): void {
		const existing = this.barrierQueues.get(channelIdHex);
		if (existing) {
			existing.batches.push(held);
			return;
		}
		const queue: IBarrierQueue = {
			peerPubkey,
			channel,
			batches: [held]
		};
		this.barrierQueues.set(channelIdHex, queue);
		this.emit('transition:held', peerPubkey, channelIdHex, held.frameSequence);
		void this._awaitRelease(channelIdHex, queue).catch((error) => {
			// The loop is deliberately not awaited by anything. An escaping
			// rejection would be an unhandled promise AND a channel wedged with
			// its queue still installed, so it is caught and the queue cleared.
			if (this.barrierQueues.get(channelIdHex) === queue) {
				this.barrierQueues.delete(channelIdHex);
			}
			this.emit(
				'error',
				channel.getChannelId(),
				`durability barrier release failed: ${
					error instanceof Error ? error.message : String(error)
				}`
			);
		});
	}

	/**
	 * Wait out the barrier for a channel's held batches, then drain them in
	 * order. Batches queued while this is waiting are picked up by the same
	 * drain, so a channel never runs two releases at once.
	 */
	private async _awaitRelease(
		channelIdHex: string,
		queue: IBarrierQueue
	): Promise<void> {
		const barrier = this.config.durabilityBarrier;
		if (!barrier) return;
		while (this.barrierQueues.get(channelIdHex) === queue) {
			const next = queue.batches[0];
			if (!next) {
				this.barrierQueues.delete(channelIdHex);
				return;
			}
			if (next.requiresDurability) {
				const outcome = await barrier.whenReleased(next.frameSequence);
				// The queue may have been discarded while we waited: a disconnect
				// rolls channel state backward under it, so what is parked here no
				// longer describes the channel.
				if (this.barrierQueues.get(channelIdHex) !== queue) return;
				if (!outcome.released) {
					this._discardHeld(channelIdHex, queue, outcome.reason);
					return;
				}
			}
			queue.batches.shift();
			try {
				this._dispatchHeld(queue, next);
			} catch (error) {
				// The batch was PARTIALLY dispatched. Draining on would let a
				// later batch reach the peer with its predecessor missing, so
				// the whole queue stops here.
				this._abandonAfterPartialDispatch(channelIdHex, queue, error);
				return;
			}
		}
	}

	/**
	 * A released batch threw partway through dispatch.
	 *
	 * `_dispatchActions` runs sends, broadcasts and the re-entrant emits in one
	 * sequential pass, and any of the listeners on those emits can throw back
	 * into it. When one does, an unknown prefix of the batch is already on the
	 * socket and the rest never will be, so this channel's wire stream is
	 * truncated at a point nobody can name. Everything still queued behind it
	 * MUST NOT go out: a later batch describes a transition whose predecessor
	 * the peer never saw, which is exactly the inversion the whole-suffix queue
	 * exists to prevent. So the queue is torn down and the stranded batches run
	 * for their internal effects only. Reestablish is the only reliable
	 * boundary after an uncertain partial send, and it is also why the partial
	 * batch is NOT retried on the live connection: some of its bytes may
	 * already have arrived.
	 *
	 * Its OWN event, not `transition:frozen`. A freeze means durability was
	 * refused and the node exempts a fenced writer from the disconnect, because
	 * a fence is already tearing the transport down. Here nothing else tears
	 * anything down and the remedy is unconditional, so conflating the two
	 * would leave a truncated stream on a live connection.
	 */
	private _abandonAfterPartialDispatch(
		channelIdHex: string,
		queue: IBarrierQueue,
		error: unknown
	): void {
		if (this.barrierQueues.get(channelIdHex) === queue) {
			this.barrierQueues.delete(channelIdHex);
		}
		const stranded = queue.batches;
		queue.batches = [];
		for (const batch of stranded) {
			this.runHeldSuffixWithoutSending(queue.peerPubkey, queue.channel, batch);
		}
		this.emit(
			'transition:dispatch-failed',
			queue.peerPubkey,
			channelIdHex,
			error instanceof Error ? error.message : String(error),
			stranded.length + 1
		);
	}

	/**
	 * A refused barrier. The messages are NOT sent, now or later: a timeout is
	 * not permission, and a fenced writer must never speak again.
	 *
	 * The held bytes are dropped rather than kept, which matches what a failed
	 * persist already does. Anything retransmittable is in the outbox and
	 * comes back through the reestablish path; anything that is not is
	 * reproduced by the reestablish rules or is a negotiation that will simply
	 * restart. `transition:frozen` is deliberately its OWN event rather than a
	 * reuse of `transition:blocked`: the state here DID commit, so none of the
	 * blocked path's rollback bookkeeping applies, and conflating the two
	 * would make an operator read a durability stall as a storage failure.
	 */
	private _discardHeld(
		channelIdHex: string,
		queue: IBarrierQueue,
		reason: string
	): void {
		this.barrierQueues.delete(channelIdHex);
		const dropped = queue.batches;
		queue.batches = [];
		// The WIRE half is dropped. The rest of the batch is not, and that
		// distinction is fund-critical: a held suffix also carries the
		// EDGE-TRIGGERED internal effects of the state its persist already
		// committed. handleRevokeAndAck sets htlc.forwardEmitted = true while
		// BUILDING its actions, and that flag is on disk by the time the
		// barrier is asked, so an HTLC_FORWARDED dropped here is never emitted
		// again by any later commitment round: the inbound HTLC would sit
		// unforwarded and unsettled until its CLTV. Running the suffix with
		// sends suppressed is exactly the disposition a failed persist already
		// has, and it costs nothing, since nothing reaches the peer either way.
		for (const batch of dropped) {
			this.runHeldSuffixWithoutSending(queue.peerPubkey, queue.channel, batch);
		}
		this.emit(
			'transition:frozen',
			queue.peerPubkey,
			channelIdHex,
			reason,
			dropped.length
		);
	}

	/**
	 * Run a held suffix for its internal effects only, with every SEND_MESSAGE,
	 * BROADCAST_TX and FORCE_CLOSE suppressed.
	 *
	 * This reuses the failed-persist suppression already built into
	 * _dispatchActions rather than inventing a second notion of "do everything
	 * except talk to the peer".
	 */
	private runHeldSuffixWithoutSending(
		peerPubkey: string,
		channel: Channel,
		held: IHeldBatch
	): void {
		const channelIdHex = channel.getChannelId()?.toString('hex') ?? null;
		// Contained on both edges so the pair is always balanced: a listener
		// that throws out of `begin` would otherwise leave every listener that
		// already ran holding an open transition that never closes.
		this.emitContained('transition:begin', channelIdHex);
		try {
			this._dispatchActions(
				peerPubkey,
				channel,
				held.actions,
				null,
				() => true,
				() => undefined,
				held.from,
				true
			);
		} catch {
			// One batch's internal effects failing must not strand the rest.
		} finally {
			this.emitContained('transition:end', channelIdHex);
		}
	}

	/** Run a released suffix through the ordinary dispatch path. */
	private _dispatchHeld(queue: IBarrierQueue, held: IHeldBatch): void {
		let blocked = false;
		const channelIdHex = queue.channel.getChannelId()?.toString('hex') ?? null;
		const progress: IActionDispatchProgress = {
			...newDispatchProgress(),
			index: held.from,
			completedIndex: held.from - 1
		};
		// Same bracket a live batch runs in, so a monitor change caused by the
		// released actions still rides its channel's transition instead of
		// committing as a frame of its own.
		this.emitContained('transition:begin', channelIdHex);
		try {
			this._dispatchActions(
				queue.peerPubkey,
				queue.channel,
				held.actions,
				null,
				() => blocked,
				(value: boolean) => {
					blocked = value;
				},
				held.from,
				true,
				undefined,
				progress
			);
		} catch (error) {
			// The action at progress.index threw and everything after it is
			// untouched. Those actions still owe their committed edge-triggered
			// effects, the same reason a refusal runs what it drops: an
			// HTLC_FORWARDED skipped here is never emitted again, because
			// forwardEmitted was set while the batch was BUILT and is already on
			// disk. So the tail runs with sends suppressed before the error goes
			// up to abandon the queue.
			this.runHeldSuffixWithoutSending(queue.peerPubkey, queue.channel, {
				...held,
				from: progress.index + 1
			});
			throw error;
		} finally {
			this.emitContained('transition:end', channelIdHex);
		}
		// Marked sent only now that the bytes are actually on the socket. A
		// row reading sent_unacked while its message is still parked would make
		// restart reestablish accounting believe the peer had seen it.
		if (held.outboxIds.length) this.emit('outbox:sent', held.outboxIds);
	}

	/** Channel ids currently holding messages behind the barrier. */
	channelsAwaitingDurability(): Set<string> {
		return new Set(this.barrierQueues.keys());
	}

	/**
	 * Ask again for an authorization a restart lost, for one channel.
	 *
	 * Returns whether a request was dispatched. Callers use that to keep one
	 * outstanding request per transaction rather than minting a fresh frame on
	 * every block while the first one is still waiting on the quorum.
	 */
	reauthorizeFundingBroadcast(channelId: Buffer): boolean {
		return this._dispatchReauthorization(channelId, (channel) =>
			channel.buildFundingReauthorizationActions()
		);
	}

	/** The splice equivalent, for a fully signed splice resumed at startup. */
	reauthorizeSpliceBroadcast(channelId: Buffer): boolean {
		return this._dispatchReauthorization(channelId, (channel) =>
			channel.buildSpliceRebroadcastActions()
		);
	}

	private _dispatchReauthorization(
		channelId: Buffer,
		build: (channel: Channel) => ChannelAction[]
	): boolean {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) return false;
		const peerPubkey = this.channelPeers.get(idHex);
		if (!peerPubkey) return false;
		const actions = build(channel);
		if (actions.length === 0) return false;
		this.processActions(peerPubkey, channel, actions);
		return true;
	}

	/**
	 * Unhook a channel's barrier queue because it is force closing, and hand
	 * the caller what was parked. PURE, in the only sense that matters here:
	 * it dispatches nothing and emits nothing.
	 *
	 * That is the whole point of the split. This runs between a force-close
	 * plan being made and being applied, and a plan is a decision about the
	 * state that existed when it was planned. Anything with a callback in it
	 * (a dispatched action, an emitted event) opens a window in that gap:
	 * a listener that throws leaves the queue deleted and the close never
	 * applied, and one that synchronously re-enters this manager moves the
	 * channel out from under a commitment already built against it. Node
	 * emits synchronously, so both are ordinary control flow, not races.
	 *
	 * Removing the queue also retires the release loop, whose own guard stops
	 * it from dispatching into a queue this has replaced.
	 */
	private _detachQueueForTerminalClose(channelIdHex: string): {
		peerPubkey: string;
		channel: Channel;
		batches: IHeldBatch[];
	} | null {
		const queue = this.barrierQueues.get(channelIdHex);
		if (!queue) return null;
		this.barrierQueues.delete(channelIdHex);
		const batches = queue.batches;
		queue.batches = [];
		return { peerPubkey: queue.peerPubkey, channel: queue.channel, batches };
	}

	/**
	 * Settle what the detached queue still owed, AFTER the close is on its way.
	 *
	 * Everything parked runs for its committed edge-triggered effects only and
	 * its wire half is abandoned permanently: once the commitment is on chain
	 * the off-chain stream is over, and releasing an older message after it
	 * would describe a channel that no longer exists.
	 *
	 * Every observer failure is contained. By the time this runs the
	 * commitment has been authorized and dispatched, so an exception escaping
	 * a diagnostic listener could only undo bookkeeping for a close that has
	 * already happened. Re-entrancy is answered the same way, by ordering: a
	 * listener that comes back into this channel now meets a FORCE_CLOSED one
	 * and is declined on its own merits, rather than editing the state a plan
	 * was built from.
	 *
	 * Its OWN event, because this is neither a durability refusal nor a
	 * dispatch failure: nothing went wrong, an operator asked for the exit.
	 */
	private _settleDetachedQueueAfterTerminalClose(
		channelIdHex: string,
		detached: {
			peerPubkey: string;
			channel: Channel;
			batches: IHeldBatch[];
		} | null
	): void {
		if (!detached) return;
		for (const batch of detached.batches) {
			try {
				this.runHeldSuffixWithoutSending(
					detached.peerPubkey,
					detached.channel,
					batch
				);
			} catch {
				// One batch's observers must not strand the rest, and none of
				// them may reach back out past a close that is already done.
			}
		}
		this.emitContained(
			'transition:terminal-override',
			detached.peerPubkey,
			channelIdHex,
			detached.batches.length
		);
	}

	/**
	 * emit, for the terminal teardown paths, where a throwing listener must
	 * not propagate. Everything these announce has already happened.
	 */
	private emitContained(event: string, ...args: unknown[]): void {
		try {
			this.emit(event, ...args);
		} catch {
			// Contained deliberately: see the callers.
		}
	}

	/**
	 * Dispatch the terminal force-close batch.
	 *
	 * Deliberately not processActions. Everything that path adds is for cases
	 * this batch does not have: it carries no persist, nothing in it is
	 * barrier-class, and its queue has just been detached, so there is nothing
	 * to attribute, hold or park. The direct path also keeps the terminal send
	 * independent from ordinary batch bookkeeping. The transition pair is
	 * emitted for the same listeners, contained on both edges so it stays
	 * balanced whatever an observer does.
	 */
	private _dispatchTerminalForceClose(
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[]
	): void {
		if (this.config.nodePrivateKey) {
			if (!this.localNodeIdCache) {
				this.localNodeIdCache = getPublicKey(this.config.nodePrivateKey);
			}
			channel.setLocalNodeIdLower(
				Buffer.compare(this.localNodeIdCache, Buffer.from(peerPubkey, 'hex')) <
					0
			);
		}
		// Staged for a batch that is not happening now: a supersede belongs to
		// the transition that staged it, and this one deletes nothing.
		this._pendingOutboxSupersede = null;
		const channelIdHex = channel.getChannelId()?.toString('hex') ?? null;
		this.emitContained('transition:begin', channelIdHex);
		try {
			this._dispatchActions(
				peerPubkey,
				channel,
				actions,
				null,
				() => false,
				() => undefined
			);
		} finally {
			this.emitContained('transition:end', channelIdHex);
		}
	}

	/**
	 * Drop everything held for a channel. Called on disconnect, where
	 * markForReestablish rolls uncommitted updates back, deletes uncommitted
	 * received HTLCs and resets the splice driver: held messages describe the
	 * view BEFORE that rollback, so flushing them would put a description of
	 * state the channel no longer has onto the wire.
	 */
	private purgeBarrierQueue(channelIdHex: string): void {
		const queue = this.barrierQueues.get(channelIdHex);
		if (!queue) return;
		this.barrierQueues.delete(channelIdHex);
		const dropped = queue.batches;
		queue.batches = [];
		// Same rule as a refusal: the wire half goes, the internal effects do
		// not. Called BEFORE markForReestablish, so a committed received HTLC
		// still forwards; the rollback only discards UNcommitted updates, which
		// were never going to forward anyway.
		for (const batch of dropped) {
			this.runHeldSuffixWithoutSending(queue.peerPubkey, queue.channel, batch);
		}
	}

	private processChainActions(channelId: Buffer, actions: ChainAction[]): void {
		for (const action of actions) {
			switch (action.type) {
				case ChainActionType.BROADCAST_TX:
					this.emit('broadcast:tx', action.tx);
					break;
				case ChainActionType.FEE_BUMP_AND_BROADCAST:
					// Async: attach a wallet fee input then broadcast. Fire-and-forget;
					// failures fall back to broadcasting the unbumped tx internally.
					void this._handleFeeBumpAndBroadcast(channelId, action);
					break;
				case ChainActionType.WATCH_OUTPUT:
					this.emit('watch:output', action.txid, action.outputIndex);
					break;
				case ChainActionType.WATCH_TX:
					this.emit('watch:tx', action.txid);
					break;
				case ChainActionType.OUTPUT_RESOLVED:
					this.emit(
						'output:resolved',
						action.txid,
						action.outputIndex,
						action.channelId,
						action.outputType,
						action.paymentHash,
						action.htlcId
					);
					break;
				case ChainActionType.CHANNEL_FULLY_RESOLVED:
					this.emit('channel:resolved', action.channelId);
					break;
				case ChainActionType.PREIMAGE_LEARNED:
					this.emit('preimage:learned', action.paymentHash, action.preimage);
					break;
				case ChainActionType.REBUILD_SWEEP: {
					// A previously-broadcast sweep has not confirmed; re-resolve it at
					// the bumped feerate and rebroadcast (RBF). Critical for penalty
					// txs that must confirm before the cheater's to_self_delay matures.
					const mon = this.monitors.get(channelId.toString('hex'));
					const rebuilt =
						mon && typeof mon.rebuildSweeps === 'function'
							? mon.rebuildSweeps(action.output, action.feeRatePerVbyte)
							: [
									mon?.rebuildSweep(action.output, action.feeRatePerVbyte)
							  ].filter(
									(tx): tx is import('bitcoinjs-lib').Transaction => !!tx
							  );
					for (const tx of rebuilt) {
						// Sweep rebuilds return bitcoin.Transaction objects; every
						// broadcast listener expects a raw Buffer.
						this.emit('broadcast:tx', tx.toBuffer());
					}
					break;
				}
				case ChainActionType.SWEEP_UNECONOMIC:
					// A claim we declined because it cannot pay its own fee. Surfaced
					// so an operator can see the decline (and, at 'abandoned', that it
					// will not be retried again) instead of it passing silently.
					this.emit('sweep:uneconomic', channelId, action);
					break;
				case ChainActionType.ERROR:
					this.emit('error', channelId, action.message);
					break;
			}
		}
	}

	/**
	 * Attach a wallet-funded fee bump to an anchor transaction, then broadcast it.
	 *
	 * For `htlc-fee-attach` the pre-signed zero-fee second-level HTLC tx has wallet
	 * inputs + change appended so it pays its own fee. For `anchor-cpfp` a child
	 * spending our local anchor is built and broadcast alongside the commitment.
	 *
	 * Resolution is detected by watching the spent commitment output, so the bumped
	 * transaction's different txid needs no re-tracking. Any failure (no funding
	 * provider, insufficient UTXOs, build error) falls back to broadcasting the
	 * unbumped transaction so a force-close is never stranded.
	 */
	private async _handleFeeBumpAndBroadcast(
		channelId: Buffer,
		action: IFeeBumpAndBroadcastChainAction
	): Promise<void> {
		const fp = this.fundingProvider;
		const feeratePerVbyte = action.feeratePerVbyte;
		const feeratePerKw = satPerVbyteToSatPerKw(feeratePerVbyte);

		if (!fp?.selectFeeBumpInputs) {
			this.emit(
				'error',
				channelId,
				`anchor fee bump (${action.kind}) skipped: no funding provider; broadcasting unbumped`
			);
			this.emit('broadcast:tx', action.tx);
			return;
		}

		try {
			if (action.kind === 'htlc-fee-attach') {
				const htlcTx = bitcoin.Transaction.fromBuffer(action.tx);
				const htlcWitness = htlcTx.ins[0]?.witness;
				if (!htlcWitness || htlcWitness.length === 0) {
					// No pre-signed witness — bumping cannot make it valid.
					this.emit('broadcast:tx', action.tx);
					return;
				}
				// The wallet must cover the whole fee (the HTLC tx pays zero). Pass the
				// HTLC tx's own fee; the provider adds the wallet input/change weight.
				const targetFeeSats = BigInt(
					Math.ceil(htlcTx.virtualSize() * feeratePerVbyte)
				);
				const { inputs, changeScript } = await fp.selectFeeBumpInputs(
					targetFeeSats,
					feeratePerKw
				);
				const { tx } = attachFeeInputsToZeroFeeHtlcTx({
					htlcTx,
					htlcWitness,
					walletInputs: inputs,
					changeScript,
					feeratePerVbyte
				});
				this.emit('broadcast:tx', tx.toBuffer());
				return;
			}

			// anchor-cpfp: build a child spending our local anchor to bump the package.
			if (
				action.anchorOutputIndex == null ||
				!action.anchorWitnessScript ||
				action.parentVbytes == null ||
				action.parentFeeSats == null ||
				!action.commitmentTxid
			) {
				throw new Error('anchor-cpfp action missing anchor metadata');
			}
			// Size the wallet-selection target to the CHILD-PACKAGE deficit, not the
			// parent-only fee. buildAnchorCpfpTx pays
			//   ceil(feerate * (parentVbytes + childVbytes)) - parentFeeSats,
			// and selectFeeBumpInputs already adds the fee for the wallet inputs and
			// change output it appends. So the target must cover the parent deficit
			// PLUS the child's own non-wallet weight (base overhead + the anchor
			// input), less the parent's already-paid fee, credited by the 330-sat
			// anchor value the child spends. The previous target (parent-only fee,
			// no child weight, no parentFeeSats credit) under-funded selection, so
			// with small P2WPKH UTXOs buildAnchorCpfpTx could throw "insufficient
			// funds" and no CPFP child was emitted while the commitment sat unbumped.
			// The actual child fee is still computed exactly from the real child
			// weight, so a generous overhead estimate only affects selection.
			const estChildOverheadVbytes = action.taprootAnchorMerkleRoot ? 70 : 85;
			const packageFeeSats = BigInt(
				Math.ceil(
					feeratePerVbyte * (action.parentVbytes + estChildOverheadVbytes)
				)
			);
			const rawTarget =
				packageFeeSats - action.parentFeeSats - ANCHOR_OUTPUT_VALUE;
			const targetFeeSats = rawTarget > 0n ? rawTarget : 0n;
			const { inputs, changeScript } = await fp.selectFeeBumpInputs(
				targetFeeSats,
				feeratePerKw
			);
			const { tx } = buildAnchorCpfpTx({
				commitmentTxid: action.commitmentTxid,
				anchorOutputIndex: action.anchorOutputIndex,
				anchorAmount: ANCHOR_OUTPUT_VALUE,
				anchorWitnessScript: action.anchorWitnessScript,
				// Taproot anchors are key-path spent by the local delayed privkey
				// on our own commitment, or by our static payment basepoint secret
				// on the peer's (issue #559); legacy anchors by the funding privkey.
				localFundingPrivkey: action.taprootAnchorMerkleRoot
					? action.taprootAnchorKeyRole === 'payment'
						? this._channelPaymentBasepointSecret(channelId)
						: this._channelTaprootAnchorPrivkey(channelId)
					: this._channelFundingPrivkey(channelId),
				parentVbytes: action.parentVbytes,
				parentFeeSats: action.parentFeeSats,
				walletInputs: inputs,
				changeScript,
				feeratePerVbyte,
				taprootAnchorScript: action.taprootAnchorScript,
				taprootAnchorMerkleRoot: action.taprootAnchorMerkleRoot
			});
			// The commitment (parent) is broadcast by the force-close path; emit only
			// the fee-bearing child so the 1-parent-1-child package clears the target.
			this.emit('broadcast:tx', tx.toBuffer());
			// The child was actually emitted: record the paid feerate + height and
			// clear any prior failure flag, so the retry gate reflects real progress.
			const pending = this._pendingCommitmentCpfp.get(
				channelId.toString('hex')
			);
			if (pending) {
				pending.lastFeeRate = feeratePerVbyte;
				pending.broadcastHeight = this._currentBlockHeight;
				pending.lastAttemptFailed = false;
			}
		} catch (err) {
			this.emit(
				'error',
				channelId,
				`anchor fee bump (${action.kind}) failed, broadcasting unbumped: ${
					(err as Error).message
				}`
			);
			// The zero-fee HTLC tx still gets a (futile but harmless) broadcast as a
			// fallback; the commitment is already broadcast for the CPFP case.
			if (action.kind === 'htlc-fee-attach')
				this.emit('broadcast:tx', action.tx);
			// anchor-cpfp failed to emit a child (e.g. no confirmed UTXOs). Flag it so
			// reCpfpStuckCommitments retries next cycle rather than treating the paid
			// feerate as advanced and blocking every future attempt. Advance
			// broadcastHeight (but NOT lastFeeRate) so retries are paced by the re-bump
			// interval instead of every block.
			if (action.kind === 'anchor-cpfp') {
				const pending = this._pendingCommitmentCpfp.get(
					channelId.toString('hex')
				);
				if (pending) {
					pending.lastAttemptFailed = true;
					pending.broadcastHeight = this._currentBlockHeight;
				}
			}
		}
	}

	/**
	 * On an anchor force-close, build and broadcast a CPFP child that spends our
	 * local anchor output to raise the commitment package's effective fee rate.
	 * Best-effort: skipped silently when the channel is non-anchor, no funding
	 * provider is set, or our local anchor was trimmed from the commitment.
	 */
	private _maybeCpfpAnchorCommitment(
		channelId: Buffer,
		state: IChannelState,
		actions: ChannelAction[],
		feeRatePerVbyte: number
	): void {
		if (!isAnchorChannel(state.channelType)) return;
		if (!this.fundingProvider?.selectFeeBumpInputs) return;
		// channel.forceClose() emits the commitment as a BROADCAST_TX action.
		const fc = actions.find(
			(a): a is { type: ChannelActionType.BROADCAST_TX; tx: Buffer } =>
				a.type === ChannelActionType.BROADCAST_TX
		);
		if (!fc) return;
		try {
			const commitmentTx = bitcoin.Transaction.fromBuffer(fc.tx);
			// Simple-taproot commitments carry a P2TR anchor keyed to the local
			// to_local delayed pubkey; legacy anchor channels carry a witness-v0
			// P2WSH anchor keyed to the funding pubkey. Matching the wrong script
			// leaves findIndex at -1 and silently skips the CPFP, so a taproot
			// force-close could never be fee-bumped and would ride at its stale
			// open-time feerate through a spike.
			const taprootAnchor = isTaprootChannel(state.channelType)
				? this._localTaprootAnchor(state)
				: null;
			const anchorScript = taprootAnchor
				? taprootAnchor.script
				: buildAnchorOutput(state.localBasepoints.fundingPubkey).script;
			const anchorOutputIndex = commitmentTx.outs.findIndex((o) =>
				o.script.equals(anchorScript)
			);
			if (anchorOutputIndex < 0) return; // our anchor trimmed — nothing to CPFP with
			const outsSum = commitmentTx.outs.reduce(
				(s, o) => s + BigInt(o.value),
				0n
			);
			const parentFeeSats =
				state.fundingSatoshis > outsSum ? state.fundingSatoshis - outsSum : 0n;
			const cpfpAction: IFeeBumpAndBroadcastChainAction = {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'anchor-cpfp',
				tx: fc.tx,
				description: 'anchor commitment CPFP',
				feeratePerVbyte: feeRatePerVbyte,
				anchorOutputIndex,
				anchorWitnessScript: taprootAnchor
					? Buffer.alloc(0)
					: buildAnchorScript(state.localBasepoints.fundingPubkey),
				parentVbytes: commitmentTx.virtualSize(),
				parentFeeSats,
				commitmentTxid: commitmentTx.getId(),
				...(taprootAnchor
					? {
							taprootAnchorScript: taprootAnchor.script,
							taprootAnchorMerkleRoot: taprootAnchor.merkleRoot
					  }
					: {})
			};
			void this._handleFeeBumpAndBroadcast(channelId, cpfpAction);
			// Retain it so a stuck commitment package can be re-CPFP'd at a higher
			// feerate each block until it confirms (reCpfpStuckCommitments).
			this._pendingCommitmentCpfp.set(channelId.toString('hex'), {
				action: cpfpAction,
				broadcastHeight: this._currentBlockHeight,
				lastFeeRate: feeRatePerVbyte
			});
		} catch (err) {
			this.emit(
				'error',
				channelId,
				`anchor commitment CPFP setup failed: ${(err as Error).message}`
			);
		}
	}

	/**
	 * The peer's commitment was seen in the MEMPOOL on an anchor channel and we
	 * hold the preimage of an inbound HTLC riding on it (issue #559). Our claim
	 * of that HTLC spends their commitment with a 1-CSV, so it cannot even be
	 * broadcast until their commitment confirms — timing the PEER controls: an
	 * adversarial one parks a below-floor commitment, waits out cltv_expiry,
	 * then bumps it and races our claim with their pre-signed HTLC-timeout.
	 * Their commitment carries an anchor keyed to US for exactly this: attach a
	 * wallet-funded CPFP child so the package confirms while the deadline is
	 * still comfortably ahead. Tracked in _pendingCommitmentCpfp so
	 * reCpfpStuckCommitments re-bids (and re-inserts an evicted parent) until
	 * it confirms. Best-effort, like _maybeCpfpAnchorCommitment.
	 */
	private _maybeCpfpTheirCommitment(
		channelId: Buffer,
		state: IChannelState,
		commitmentTx: bitcoin.Transaction,
		feeRatePerVbyte: number
	): void {
		if (!isAnchorChannel(state.channelType)) return;
		if (!this.fundingProvider?.selectFeeBumpInputs) return;
		const idHex = channelId.toString('hex');
		// A tracked package (ours from a force-close, or theirs from an earlier
		// report of this same sighting) is already being re-bid.
		if (this._pendingCommitmentCpfp.has(idHex)) return;
		// Spend wallet fees only when confirmation is deadline-bound: an inbound
		// HTLC whose preimage we hold must be claimed before its cltv_expiry.
		// Everything else on their commitment can wait for their fee bump.
		let deadlineBound = false;
		for (const [key, htlc] of state.htlcs) {
			if (!key.startsWith('received-')) continue;
			const hashHex = htlc.paymentHash?.toString('hex');
			if (
				htlc.state === HtlcState.FULFILLED ||
				(hashHex !== undefined && this._knownPreimages.has(hashHex))
			) {
				deadlineBound = true;
				break;
			}
		}
		if (!deadlineBound) return;
		try {
			// On THEIR commitment our anchor is the remote-side one. Legacy anchor
			// channels key each anchor to that side's funding pubkey, so ours is
			// the same script as on our own commitment; taproot channels key the
			// remote anchor to our STATIC to_remote payment basepoint
			// (deriveCommitmentKeys uses the basepoint raw), not the delayed key.
			const taprootAnchor = isTaprootChannel(state.channelType)
				? buildTaprootAnchorOutput(state.localBasepoints.paymentBasepoint)
				: null;
			const anchorScript = taprootAnchor
				? taprootAnchor.output
				: buildAnchorOutput(state.localBasepoints.fundingPubkey).script;
			const anchorOutputIndex = commitmentTx.outs.findIndex((o) =>
				o.script.equals(anchorScript)
			);
			if (anchorOutputIndex < 0) return; // our anchor trimmed — nothing to bump with
			const outsSum = commitmentTx.outs.reduce(
				(s, o) => s + BigInt(o.value),
				0n
			);
			const parentFeeSats =
				state.fundingSatoshis > outsSum ? state.fundingSatoshis - outsSum : 0n;
			const cpfpAction: IFeeBumpAndBroadcastChainAction = {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST,
				kind: 'anchor-cpfp',
				tx: commitmentTx.toBuffer(),
				description: 'peer commitment anchor CPFP',
				feeratePerVbyte: feeRatePerVbyte,
				anchorOutputIndex,
				anchorWitnessScript: taprootAnchor
					? Buffer.alloc(0)
					: buildAnchorScript(state.localBasepoints.fundingPubkey),
				parentVbytes: commitmentTx.virtualSize(),
				parentFeeSats,
				commitmentTxid: commitmentTx.getId(),
				...(taprootAnchor
					? {
							taprootAnchorScript: taprootAnchor.output,
							taprootAnchorMerkleRoot: taprootAnchor.merkleRoot,
							taprootAnchorKeyRole: 'payment' as const
					  }
					: {})
			};
			void this._handleFeeBumpAndBroadcast(channelId, cpfpAction);
			this._pendingCommitmentCpfp.set(idHex, {
				action: cpfpAction,
				broadcastHeight: this._currentBlockHeight,
				lastFeeRate: feeRatePerVbyte
			});
		} catch (err) {
			this.emit(
				'error',
				channelId,
				`peer commitment anchor CPFP setup failed: ${(err as Error).message}`
			);
		}
	}

	/**
	 * Re-CPFP any anchor force-close commitment package that is still unconfirmed,
	 * bidding a higher (live) feerate so a fee spike AFTER the original broadcast
	 * cannot pin the commitment. The initial CPFP is one-shot; without this a stuck
	 * commitment blocks every second-level HTLC claim (which spends a commitment
	 * output) and an HTLC we hold the preimage for is lost to the peer's timeout.
	 *
	 * Driven by the node each block with a live feerate (the ChannelManager has no fee
	 * estimator). An entry is dropped once its monitor is gone or fully resolved, once
	 * a DIFFERENT transaction confirms as the funding spend, or once the tracked
	 * commitment is buried IRREVOCABLE_DEPTH deep. The entry may also carry the
	 * PEER's mempool commitment (_maybeCpfpTheirCommitment, issue #559); the same
	 * re-bid applies, and the parent re-broadcast re-inserts it if evicted.
	 *
	 * @param blockHeight - current chain tip
	 * @param feeRatePerVbyte - live force-close feerate from the node's estimator
	 */
	reCpfpStuckCommitments(blockHeight: number, feeRatePerVbyte: number): void {
		this._currentBlockHeight = blockHeight;
		for (const [channelIdHex, entry] of this._pendingCommitmentCpfp) {
			const monitor = this.monitors.get(channelIdHex);
			// Stop CPFP only once the monitor is gone or fully resolved. Do NOT stop
			// merely because the funding spend was DETECTED: the monitor leaves WATCHING
			// the instant our own commitment is seen in the mempool (chain-watcher feeds
			// unconfirmed spends), which is exactly when a fee spike can pin the package
			// and re-CPFP is needed. Gating on WATCHING alone made this re-bump inert.
			if (!monitor || monitor.isFullyResolved()) {
				this._pendingCommitmentCpfp.delete(channelIdHex);
				continue;
			}
			if (monitor.isCommitmentConfirmed()) {
				// A first confirmation is NOT the end of this. A reorg can evict the
				// block and drop a floor-feerate commitment (and its now-underpriced
				// child) back into a spiked mempool that accepts neither, and nothing
				// else re-arms OUR package: the re-report path only re-CPFPs peer
				// commitments, and rearmCommitmentCpfp runs on restore. Deleting at
				// 1-conf left the demoted commitment unbumped past cltv_expiry, so the
				// peer's HTLC-timeout took an HTLC we held the preimage for (issue
				// #578). Park the entry instead; the demotion branch below resumes it.
				//
				// Two things do end it: a DIFFERENT transaction confirming as the
				// funding spend (ours lost the race, or a splice adoption replaced it
				// per issue #357), which this package can never outrace, and the
				// recorded confirmation reaching IRREVOCABLE_DEPTH.
				const broadcast = monitor.getFullState().commitmentBroadcast;
				const confirmedAt = broadcast ? broadcast.blockHeight : 0;
				if (
					broadcast?.txid !== entry.action.commitmentTxid ||
					blockHeight - confirmedAt >= IRREVOCABLE_DEPTH
				) {
					this._pendingCommitmentCpfp.delete(channelIdHex);
					continue;
				}
				entry.sawConfirmation = true;
				continue;
			}
			// The tracked commitment confirmed earlier and now reads unconfirmed: a
			// reorg demoted it, or a valid competing spend appeared in the mempool.
			// Both gates below describe a package that is merely slow; a demoted one
			// may not be in any mempool at all, so re-broadcast and re-bid at once.
			const demoted = entry.sawConfirmation === true;
			entry.sawConfirmation = false;
			if (demoted) {
				// The flag only says the tracked commitment was the recorded spend
				// when it was set. A DIFFERENT transaction can confirm as the spend
				// and then itself be demoted before the next pass runs, and the
				// confirmed branch above never sees it because the monitor already
				// reads unconfirmed. Re-broadcasting here would bid wallet funds on a
				// child of a parent the chain has superseded, so end the entry exactly
				// as that branch does. Same check _maybeRearmDemotedOurCommitment
				// makes before it sets the flag.
				const recorded = monitor.getFullState().commitmentBroadcast;
				if (recorded && recorded.txid !== entry.action.commitmentTxid) {
					this._pendingCommitmentCpfp.delete(channelIdHex);
					continue;
				}
			} else {
				// Only re-bump after a stall.
				if (
					blockHeight - entry.broadcastHeight <
					COMMITMENT_CPFP_REBUMP_INTERVAL
				) {
					continue;
				}
				// Re-bump if the live feerate beats what we last paid, OR the previous
				// attempt failed to emit a child at all (e.g. no confirmed UTXOs then).
				// Without the failure escape a failed attempt still advanced lastFeeRate,
				// so the `<=` gate blocked every retry even after wallet change confirmed.
				if (feeRatePerVbyte <= entry.lastFeeRate && !entry.lastAttemptFailed) {
					continue;
				}
			}

			const channelId = Buffer.from(channelIdHex, 'hex');
			// Re-broadcast the PARENT commitment alongside the child. A fee spike can
			// evict both parent and child; the CPFP child alone is an orphan
			// (missing-inputs) and never re-enters the mempool, so bumping only the
			// child left the commitment stuck forever while lastFeeRate advanced.
			// Re-broadcasting an already-confirmed parent is rejected harmlessly.
			this.emit('broadcast:tx', entry.action.tx);
			// lastFeeRate / broadcastHeight / lastAttemptFailed are updated by
			// _handleFeeBumpAndBroadcast ONLY once a child is actually emitted, so a
			// failed attempt does not masquerade as a paid one.
			void this._handleFeeBumpAndBroadcast(channelId, {
				...entry.action,
				feeratePerVbyte: feeRatePerVbyte,
				description: 'anchor commitment CPFP (re-bump)'
			});
		}
	}

	/**
	 * After a restore: re-broadcast OUR still-unconfirmed anchor force-close
	 * commitment and re-arm its CPFP tracking. _pendingCommitmentCpfp is
	 * in-memory only, so without this a restart while the commitment sits
	 * unconfirmed leaves the package unbumped (and possibly mempool-evicted)
	 * forever — CSV/HTLC sweeps are all blocked behind the unconfirmed parent.
	 * Safe to re-run: forceClose() rebuilds the byte-identical commitment
	 * (deterministic signatures) and duplicate broadcasts are rejected
	 * harmlessly by the network.
	 */
	rearmCommitmentCpfp(channelId: Buffer, feeRatePerVbyte: number): void {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		const monitor = this.monitors.get(idHex);
		if (!channel || !monitor) return;
		// Only OUR force-close broadcasts a commitment we can CPFP.
		// markClosedOnChain(true) also sets FORCE_CLOSED for a REMOTE force-close,
		// so gate on the monitor having classified OUR commitment as the spend —
		// otherwise, for a peer's still-unconfirmed (mempool-only) force-close we
		// would re-broadcast our competing commitment over theirs, and if theirs
		// was a revoked breach we would forgo the justice claim. isCommitmentConfirmed
		// alone does not distinguish ours from theirs.
		if (channel.getState() !== ChannelState.FORCE_CLOSED) return;
		const broadcast = monitor.getFullState().commitmentBroadcast;
		if (
			broadcast &&
			broadcast.commitmentType !== CommitmentType.OUR_COMMITMENT
		) {
			return;
		}
		if (monitor.isFullyResolved() || monitor.isCommitmentConfirmed()) return;
		if (this._pendingCommitmentCpfp.has(idHex)) return;

		const signer = this.signerFor(channel, true);
		const actions = channel.forceClose(signer);
		if (actions.some((a) => a.type === ChannelActionType.ERROR)) return;
		// Re-broadcast the commitment itself (it may have been evicted while we
		// were offline), then attach the CPFP child and re-arm per-block re-bumps.
		for (const action of actions) {
			if (action.type === ChannelActionType.BROADCAST_TX) {
				this.emit('broadcast:tx', action.tx);
			}
		}
		this._maybeCpfpAnchorCommitment(
			channelId,
			channel.getFullState(),
			actions,
			feeRatePerVbyte
		);
	}

	/**
	 * Rebuild the latest commitment of a FORCE_CLOSED channel for a manual
	 * rebroadcast (the on-demand counterpart of rearmCommitmentCpfp, same
	 * guards). The rebuild is byte-identical (deterministic signatures) and
	 * derives only from current persisted state, so no older/revoked
	 * commitment can ever be produced. Deliberately does NOT touch
	 * this.monitors (forceClose() would replace the live monitor and discard
	 * its tracked outputs) and does NOT emit broadcast:tx: the caller
	 * broadcasts exactly once, awaitably, so a duplicate does not land in the
	 * watcher's failed-broadcast retry queue as a false BROADCAST_FAILED.
	 */
	rebuildForceCloseCommitment(
		channelId: Buffer,
		feeRatePerVbyte: number
	): { ok: boolean; tx?: Buffer; error?: string; retryable?: boolean } {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			return { ok: false, error: `Channel not found: ${idHex}` };
		}
		if (channel.getState() !== ChannelState.FORCE_CLOSED) {
			return { ok: false, error: 'Channel is not force-closed' };
		}
		// A restored FORCE_CLOSED channel may have NO monitor: the crash
		// window between the terminal persist and the first spend
		// observation, which restoreChainWatches deliberately leaves for lazy
		// creation on spend detection. With no recorded spend evidence there
		// is nothing to refuse on; the rebuild derives from current persisted
		// state exactly as the original close did.
		const monitor = this.monitors.get(idHex);
		if (monitor) {
			// Same reasoning as rearmCommitmentCpfp: once the monitor classified
			// a spend that is NOT our commitment (the peer's close, possibly a
			// revoked breach), rebroadcasting ours would compete with it.
			const broadcast = monitor.getFullState().commitmentBroadcast;
			if (
				broadcast &&
				broadcast.commitmentType !== CommitmentType.OUR_COMMITMENT
			) {
				return { ok: false, error: 'Close was not our commitment' };
			}
			if (monitor.isFullyResolved() || monitor.isCommitmentConfirmed()) {
				// A bare confirmation can be STALE: a reorg can replace the
				// confirmed commitment (e.g. with a splice spending the same
				// funding outpoint), and the funding-spend reconcile demotes the
				// recorded height only afterwards. Resolution is depth-gated
				// (issue #338), so fully-resolved is conclusive; a bare
				// confirmation is worth the caller retrying.
				return {
					ok: false,
					error: 'Close already confirmed',
					retryable: !monitor.isFullyResolved()
				};
			}
		}
		const signer = this.signerFor(channel, true);
		const actions = channel.forceClose(signer);
		const errAction = actions.find(
			(a): a is IErrorAction => a.type === ChannelActionType.ERROR
		);
		if (errAction) {
			return { ok: false, error: errAction.message };
		}
		const txAction = actions.find(
			(a): a is IBroadcastTxAction => a.type === ChannelActionType.BROADCAST_TX
		);
		if (!txAction) {
			return { ok: false, error: 'Force close rebuilt no transaction' };
		}
		// The rebuild can move the close onto a DIFFERENT commitment (splice
		// adoption, issue #357): a CPFP entry retained for the old parent
		// would keep re-broadcasting and fee-bumping the voided commitment
		// while the adopted one rides with no CPFP child at all. Replace it.
		const rebuiltTxid = bitcoin.Transaction.fromBuffer(txAction.tx).getId();
		const existingCpfp = this._pendingCommitmentCpfp.get(idHex);
		if (existingCpfp && existingCpfp.action.commitmentTxid !== rebuiltTxid) {
			this._pendingCommitmentCpfp.delete(idHex);
		}
		if (!this._pendingCommitmentCpfp.has(idHex)) {
			this._maybeCpfpAnchorCommitment(
				channelId,
				channel.getFullState(),
				actions,
				feeRatePerVbyte
			);
		}
		return { ok: true, tx: txAction.tx };
	}

	/** Resolve the funding private key for a channel (per-channel keys or node key). */
	private _channelFundingPrivkey(channelId: Buffer): Buffer {
		const channel = this.channels.get(channelId.toString('hex'));
		const keyIndex = channel?.channelKeyIndex;
		if (this.config.channelKeyDeriver && keyIndex != null) {
			return this.config.channelKeyDeriver(keyIndex).fundingPrivkey;
		}
		return this.config.localFundingPrivkey;
	}

	/**
	 * Per-commitment point of OUR current local commitment. The commitment
	 * broadcast on force-close is at height localCommitmentNumber, so its
	 * per-commitment secret index is MAX_INDEX - localCommitmentNumber.
	 */
	private _localCommitmentPoint(state: IChannelState): Buffer {
		return perCommitmentPointFromSecret(
			generateFromSeed(
				state.localPerCommitmentSeed,
				0xffffffffffffn - state.localCommitmentNumber
			)
		);
	}

	/**
	 * Simple-taproot anchor script + tree merkle root for OUR local anchor on the
	 * broadcast commitment. The taproot local anchor's internal key is the
	 * to_local delayed pubkey (LND CommitScriptAnchors keySelector), NOT the
	 * funding key legacy anchors use.
	 */
	private _localTaprootAnchor(state: IChannelState): {
		script: Buffer;
		merkleRoot: Buffer;
	} {
		const point = this._localCommitmentPoint(state);
		const localDelayedPubkey = derivePublicKey(
			state.localBasepoints.delayedPaymentBasepoint,
			point
		);
		const anchor = buildTaprootAnchorOutput(localDelayedPubkey);
		return { script: anchor.output, merkleRoot: anchor.merkleRoot };
	}

	/**
	 * The private key that spends OUR taproot anchor: the to_local delayed payment
	 * privkey for the broadcast commitment. Uses the same delayed-secret
	 * resolution the chain monitor uses for the to_local sweep, so the derived key
	 * matches the anchor's internal (delayed) pubkey.
	 */
	private _channelTaprootAnchorPrivkey(channelId: Buffer): Buffer {
		const channel = this.channels.get(channelId.toString('hex'));
		if (!channel) {
			throw new Error('taproot anchor CPFP: channel not found');
		}
		const state = channel.getFullState();
		const perCh = this.perChannelMonitorKeys(channel);
		const delayedSecret =
			perCh?.delayedPaymentBasepointSecret ||
			this.config.delayedPaymentBasepointSecret ||
			this.config.localFundingPrivkey;
		const point = this._localCommitmentPoint(state);
		return derivePrivateKey(
			delayedSecret,
			point,
			state.localBasepoints.delayedPaymentBasepoint
		);
	}

	/**
	 * The private key that spends OUR anchor on the PEER's taproot commitment
	 * (issue #559): the remote anchor there is keyed to our static to_remote
	 * payment basepoint, so the basepoint secret itself signs (no
	 * per-commitment derivation — deriveCommitmentKeys uses the basepoint raw).
	 * Same secret resolution the chain monitor uses for the to_remote sweep.
	 */
	private _channelPaymentBasepointSecret(channelId: Buffer): Buffer {
		const channel = this.channels.get(channelId.toString('hex'));
		const perCh = this.perChannelMonitorKeys(channel);
		return (
			perCh?.paymentBasepointSecret ||
			this.config.paymentBasepointSecret ||
			this.config.localFundingPrivkey
		);
	}

	private sendMessage(
		peerPubkey: string,
		type: MessageType,
		payload: Buffer
	): void {
		if (this.peerManager) {
			try {
				this.peerManager.sendToPeer(peerPubkey, type, payload);
			} catch {
				// Peer not connected; emit for external handling
				this.emit('message:outbound', peerPubkey, type, payload);
			}
		} else {
			this.emit('message:outbound', peerPubkey, type, payload);
		}
	}
}
