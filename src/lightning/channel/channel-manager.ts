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
import { decodeErrorMessage, encodeErrorMessage } from '../message/error';
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
	IChannelPersistEvent,
	IChannelPersistRequest,
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
import { Channel, ITaprootClosingCache } from './channel';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from './channel-state';
import { isValidShutdownScript } from './validation';
import {
	IChannelConfig,
	DEFAULT_CHANNEL_CONFIG,
	ChannelResult,
	ChannelState,
	ChannelRole,
	HtlcDirection,
	isAnchorChannel,
	isTaprootChannel,
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
	decodeTxAbortMessage,
	encodeTxAbortMessage
} from '../message/interactive-tx';
import { IDualFundingParams } from './dual-funding';
import { ILeaseRates } from '../gossip/types';
import { signWillFund, verifyWillFund } from './liquidity-ads';
import { decodeAnnouncementSignaturesMessage } from '../gossip/messages';
import { Feature, FeatureFlags } from '../features/flags';

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

/** Why a new channel is refused once the recovery namespace is finished. */
const NAMESPACE_LOST_REFUSAL =
	'recovery: this namespace lost its guardian backfill, so a new channel ' +
	'could never be proven durable; close the existing channels and provision ' +
	'a new namespace';

/** Why a dual-funded open is refused while quorum durability is enforced. */
export const QUORUM_NO_DUAL_FUND_REFUSAL =
	'recovery: quorum durability does not open dual-funded (v2) channels, ' +
	'because the interactive-funding session is not durable and BOLT 2 ' +
	'resumption of the signature exchange is not implemented; open a v1 ' +
	'channel, or run this node in async-remote durability';

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
 * - 'channel:scid-assigned' (channelId: Buffer, shortChannelId: Buffer)
 * - 'channel:pending-close' (channelId: Buffer, initiator: 'local' | 'remote')
 * - 'channel:force-closing' (channelId: Buffer, initiator: 'local' | 'remote')
 * - 'channel:closed' (channelId: Buffer)
 * - 'htlc:forwarded' (channelId: Buffer, htlcId: bigint, amountMsat: bigint, paymentHash: Buffer)
 * - 'htlc:fulfilled' (channelId: Buffer, htlcId: bigint, preimage: Buffer)
 * - 'htlc:failed' (channelId: Buffer, htlcId: bigint, reason: Buffer)
 * - 'error' (channelId: Buffer | null, message: string)
 */

/**
 * Blocks to wait between re-CPFP attempts on a stuck anchor force-close commitment
 * package (matches the ChainMonitor sweep rebroadcast cadence).
 */
const COMMITMENT_CPFP_REBUMP_INTERVAL = 6;

export class ChannelManager extends EventEmitter {
	private config: IChannelManagerConfig;
	private channels: Map<string, Channel> = new Map();
	private tempChannels: Map<string, Channel> = new Map();
	private channelPeers: Map<string, string> = new Map();
	/**
	 * Channels restored from persistence in THIS process whose node-level
	 * repair pass has not run yet (see 'channel:restore-ready'). Emptied one
	 * channel at a time as each completes reestablishment, so the repair can
	 * never run for a channel that has been live all along.
	 */
	private channelsAwaitingRestoreRepair: Set<string> = new Set();
	private peerManager: PeerManager | null = null;
	private monitors: Map<string, ChainMonitor> = new Map();
	// Latest block height seen (for stamping when a force-close CPFP was broadcast).
	private _currentBlockHeight = 0;
	// Anchor force-close commitment CPFPs awaiting confirmation, keyed by channelId
	// hex. Retained so a stuck commitment package can be re-CPFP'd at a higher feerate
	// each block (reCpfpStuckCommitments) until the commitment confirms.
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
		if (!this.zeroConfManager.isTrustedPeer(peerPubkey)) {
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
		if (opts?.trusted && !this.zeroConfManager.isTrustedPeer(peerPubkey)) {
			throw new Error(
				`Peer ${peerPubkey} is not in the trusted set; add it with addTrustedPeer before a trusted open`
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
		if (peerPubkey) {
			this.sendMessage(
				peerPubkey,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: tempIdBuf,
					data: Buffer.from(reason, 'utf8')
				})
			);
		}
		this.tempChannels.delete(tempId);
		this.channelPeers.delete(tempId);
		this.emit('channel:aborted', tempIdBuf, reason);
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
		this.processActions(peerPubkey, channel, actions);

		// Move from temp to permanent map
		const channelId = channel.getChannelId();
		if (channelId) {
			const permId = channelId.toString('hex');
			this.channels.set(permId, channel);
			this.channelPeers.set(permId, peerPubkey);
			// Clean up temp entry
			const tempId = channel.getTemporaryChannelId().toString('hex');
			this.tempChannels.delete(tempId);
		}

		return channelId;
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
	initiateShutdown(channelId: Buffer, scriptPubkey: Buffer): ChannelResult {
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

		const actions = channel.initiateShutdown(scriptPubkey);
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
	 * Handle peer disconnection: mark all channels with this peer as AWAITING_REESTABLISH.
	 */
	handlePeerDisconnected(peerPubkey: string): void {
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
			channel.markForReestablish();
		}

		// Early-stage channels → abort (BOLT 2: no reestablish before funding_signed)
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
			if (!earlyStates.has(state)) continue;

			channel.getFullState().state = ChannelState.ERRORED;
			this.tempChannels.delete(tempId);
			this.channelPeers.delete(tempId);
			this.emit(
				'error',
				channel.getTemporaryChannelId(),
				`Peer disconnected during channel open (state: ${state})`
			);
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

			// Mark channels for reestablishment — after a restart the peer
			// connection is lost, so we must complete channel_reestablish
			// before resuming normal operations (BOLT 2 §5).
			const st = channel.getState();
			if (
				st === ChannelState.NORMAL ||
				st === ChannelState.AWAITING_FUNDING_CONFIRMED ||
				st === ChannelState.AWAITING_CHANNEL_READY ||
				st === ChannelState.SHUTTING_DOWN ||
				st === ChannelState.SPLICING
			) {
				channel.markForReestablish();
			}
			this.channels.set(channelId.toString('hex'), channel);
			this.channelPeers.set(channelId.toString('hex'), peerPubkey);
			// This channel came from persistence, so the node-level state that
			// would resolve its committed inbound HTLCs (MPP part sets, held
			// forwards, the forwarding machinery's view) died with the previous
			// process. Arm the one-shot repair; reestablish fires it.
			this.channelsAwaitingRestoreRepair.add(channelId.toString('hex'));
		}
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
	 * Notify that a funding transaction has been confirmed.
	 */
	handleFundingConfirmed(channelId: Buffer): void {
		const channel = this.channels.get(channelId.toString('hex'));
		if (!channel) return;

		const peerPubkey = this.channelPeers.get(channelId.toString('hex'));
		if (!peerPubkey) return;

		const actions = channel.fundingConfirmed();
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
		const plan = channel.prepareForceClose(signer);
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

		// Create a ChainMonitor for this channel, signing with the channel's own
		// per-channel keys when present (falling back to node-level base secrets).
		const state = channel.getFullState();

		// Anchor channels: the commitment is broadcast at a low feerate, so attach
		// a wallet-funded CPFP child spending our local anchor to speed confirmation.
		this._maybeCpfpAnchorCommitment(channelId, state, actions, feeRatePerVbyte);
		const perCh = this.perChannelMonitorKeys(channel);
		const monitor = new ChainMonitor(
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
		network?: import('bitcoinjs-lib').Network
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

		const chainActions = monitor.handleFundingSpent(spendingTx, blockHeight);
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
				if (channel.markClosedOnChain(!isCoop)) {
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
			}
		}

		this.emit('monitor:updated', channelIdHex, monitor);
		return chainActions;
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

		const allActions: ChainAction[] = [];

		for (const [channelIdHex, monitor] of this.monitors) {
			if (monitor.isFullyResolved()) continue;

			const actions = monitor.handleNewBlock(blockHeight);
			if (actions.length > 0) {
				const channelId = Buffer.from(channelIdHex, 'hex');
				this.processChainActions(channelId, actions);
				allActions.push(...actions);
			}
			// Emit monitor:updated so LightningNode can persist
			this.emit('monitor:updated', channelIdHex, monitor);
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
				this.processChainActions(channelId, actions);
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
				if (actions.length > 0) {
					this.processChainActions(Buffer.from(channelIdHex, 'hex'), actions);
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
		this._seedMonitorPreimages(channelId, monitor);
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
			if (actions.length > 0) {
				this.processChainActions(Buffer.from(channelIdHex, 'hex'), actions);
			}
		}
	}

	/** Seed a freshly created/restored monitor with all known preimages. */
	private _seedMonitorPreimages(
		channelIdHex: string,
		monitor: ChainMonitor
	): void {
		const channelId = Buffer.from(channelIdHex, 'hex');
		let produced = false;
		for (const [hashHex, preimage] of this._knownPreimages) {
			const actions = monitor.addPreimage(
				Buffer.from(hashHex, 'hex'),
				preimage
			);
			// addPreimage mutates the matched HTLC output to SPEND_BROADCAST and
			// returns its broadcast/persist actions. Those MUST be processed (mirrors
			// recordPreimage) or, on a restored monitor whose HTLC-success was seeded
			// here, the output is marked broadcast but the tx never reaches the network
			// (and the non-anchor OUR-commitment rebroadcast path used to skip it too).
			if (actions.length > 0) {
				this.processChainActions(channelId, actions);
				produced = true;
			}
		}
		if (produced) {
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
	 * Established-channel messages that lead with a 32-byte channel_id and are
	 * only ever valid from the peer that owns that channel. Dispatching one from
	 * any other peer must be refused BEFORE it reaches the channel state machine:
	 * several of these can drive the machine to emit a BOLT 1 error (a bad
	 * commitment signature, a reestablish with next_commitment_number 0), which
	 * now force-closes the channel. Resolving the channel globally by id would
	 * let peer X close peer Y's channel with a single forged message.
	 *
	 * The interactive-tx family is included because beignet reuses it for
	 * SPLICING on existing permanent channels: their handlers search the
	 * permanent `channels` map first, so a foreign tx_abort could cancel, and a
	 * foreign tx_add_input could mutate, another peer's live splice. The guard
	 * only refuses ids that resolve to a permanent channel owned by someone
	 * else, so a v2 open still negotiating in `tempChannels` is untouched (its
	 * id is not in `channels`) and reaches its existing handler unchanged.
	 *
	 * ERROR/WARNING are excluded, since handleErrorMsg has its own BOLT 1
	 * ownership and all-channels handling. OPEN_CHANNEL(2) and ACCEPT_CHANNEL
	 * do not lead with a permanent channel_id, so they are omitted.
	 */
	private static readonly OWNED_CHANNEL_MESSAGES: ReadonlySet<number> =
		new Set<number>([
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
			// Interactive-tx: dual-use for v2 opens (temp channels, not matched
			// here) and splices (permanent channels, matched and guarded).
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
	 * Refuse an established-channel message that names a channel the sending
	 * peer does not own. Only fires when the channel_id resolves to a permanent
	 * channel bound to a DIFFERENT peer; unknown ids (temp/interactive opens,
	 * post-splice ids not yet promoted) fall through to the handler, which does
	 * its own resolution. Returns true when the message should be dropped.
	 */
	private isForeignChannelMessage(
		peerPubkey: string,
		type: number,
		payload: Buffer
	): boolean {
		if (!ChannelManager.OWNED_CHANNEL_MESSAGES.has(type)) return false;
		if (payload.length < 32) return false;
		const idHex = payload.subarray(0, 32).toString('hex');
		if (!this.channels.has(idHex)) return false;
		const owner = this.channelPeers.get(idHex);
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
		const msg = decodeOpenChannelMessage(payload);

		// Reject opens for a chain we do not operate on (same guard as the v2
		// open_channel2 path below).
		if (
			this.config.chainHash &&
			msg.chainHash &&
			!msg.chainHash.equals(this.config.chainHash)
		) {
			this.emit(
				'error',
				msg.temporaryChannelId,
				`open_channel for unknown chain ${msg.chainHash.toString('hex')}`
			);
			return;
		}
		if (this._namespaceCannotRecordANewChannel()) {
			this.emit('error', msg.temporaryChannelId, NAMESPACE_LOST_REFUSAL);
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
		const tempId = msg.temporaryChannelId.toString('hex');
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
		const msg = decodeAcceptChannelMessage(payload);
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
		const msg = decodeFundingCreatedMessage(payload);
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

		// Move to permanent channel ID map BEFORE processActions so that
		// PERSIST_STATE (which uses the permanent channelId) can find the channel
		if (channel.getChannelId()) {
			const permId = channel.getChannelId()!.toString('hex');
			this.channels.set(permId, channel);
			this.channelPeers.set(permId, peerPubkey);
			this.tempChannels.delete(msg.temporaryChannelId.toString('hex'));
		}

		this.processActions(peerPubkey, channel, actions);
	}

	private handleFundingSigned(peerPubkey: string, payload: Buffer): void {
		const msg = decodeFundingSignedMessage(payload);
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

			// Move to permanent map BEFORE processActions so that
			// PERSIST_STATE can find the channel by its permanent ID
			const permId = msg.channelId.toString('hex');
			this.channels.set(permId, ch);
			this.channelPeers.set(permId, peerPubkey);

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
		const msg = decodeChannelReadyMessage(payload);
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
		const msg = decodeUpdateAddHtlcMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateAddHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFulfillHtlc(peerPubkey: string, payload: Buffer): void {
		const msg = decodeUpdateFulfillHtlcMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFulfillHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFailHtlc(peerPubkey: string, payload: Buffer): void {
		const msg = decodeUpdateFailHtlcMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFailHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateFailMalformedHtlc(
		peerPubkey: string,
		payload: Buffer
	): void {
		const msg = decodeUpdateFailMalformedHtlcMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFailMalformedHtlc(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleCommitmentSigned(peerPubkey: string, payload: Buffer): void {
		const msg = decodeCommitmentSignedMessage(payload);
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
		const msg = decodeRevokeAndAckMessage(payload);
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
		const msg = decodeUpdateFeeMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFee(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleUpdateBlockheightMsg(
		peerPubkey: string,
		payload: Buffer
	): void {
		const msg = decodeUpdateBlockheightMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateBlockheight(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleShutdownMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeShutdownMessage(payload);
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
		const msg = decodeClosingSignedMessage(payload);
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
				this.emit(
					'error',
					msg.channelId,
					'Coop-close: peer closing signature failed to verify'
				);
				this.processActions(
					peerPubkey,
					channel,
					actions.filter((a) => a.type !== ChannelActionType.CHANNEL_CLOSED)
				);
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
			const { tx, witnessScript, fundingSatoshis, remoteFundingPubkey } =
				this.buildClosingTxAndScript(channel, feeSatoshis);
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

	private buildClosingTxAndScript(
		channel: Channel,
		feeSatoshis: bigint
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
		const remoteAmount = localIsOpener
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
		if (isTaprootChannel(channel.getFullState().channelType)) {
			return this.buildSignedTaprootMutualCloseTx(
				channel,
				feeSatoshis,
				theirSig
			);
		}
		const {
			tx,
			witnessScript,
			fundingSatoshis,
			localFundingPubkey,
			remoteFundingPubkey
		} = this.buildClosingTxAndScript(channel, feeSatoshis);
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
		const msg = decodeClosingCompleteMessage(payload);
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
		const msg = decodeClosingSigMessage(payload);
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

	private handleChannelReestablish(peerPubkey: string, payload: Buffer): void {
		const msg = decodeChannelReestablishMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);

		// BOLT 2: reestablish for a channel we consider closed (or never knew)
		// must be answered with an error so the peer force-closes and stops
		// retrying it on every reconnect. Silently ignoring it leaves the peer
		// with a zombie channel it reestablishes forever.
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
			this.sendMessage(
				peerPubkey,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: msg.channelId,
					data: Buffer.from(
						failedNotClosed
							? 'channel failed; closing on chain'
							: 'unknown or closed channel',
						'utf8'
					)
				})
			);
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

		// NOTE: no unconditional commitment_signed here. needsCommitment can be
		// true for updates the peer has NOT yet committed to us (a received
		// add/fulfill whose covering commitment_signed was lost with the
		// connection) — signing those into the peer's commitment before it
		// retransmits and we revoke violates the two-phase update flow. A
		// commitment that was legitimately deferred by the alternation gate is
		// released when the peer's (retransmitted) revoke_and_ack arrives — our
		// accurate next_revocation_number in channel_reestablish makes the peer
		// retransmit it (see handleRevokeAndAck's autoSignAndSendCommitment).

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
		if (channel.getState() === ChannelState.NORMAL) {
			this.emitRestoreRepairOnce(
				channel.getChannelId() ?? channel.getTemporaryChannelId()
			);
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
		const msg = decodeStfuMessage(payload);
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
		const msg = decodeSpliceMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		// Reject splice_init from a peer that never negotiated option_splice.
		if (!this.peerSupportsSplicing(peerPubkey)) {
			this.sendMessage(
				peerPubkey,
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: msg.channelId,
					data: Buffer.from('option_splice not negotiated', 'utf8')
				})
			);
			this.emit(
				'error',
				msg.channelId,
				'splice_init from peer without option_splice/option_quiesce'
			);
			return;
		}

		// Splices can grow capacity, so refresh the (possibly wumbo-lifted) cap
		// from the peer's live init features before validating.
		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const actions = channel.handleSplice(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleSpliceAckMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeSpliceAckMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		channel.setMaxFundingSatoshis(this.maxFundingForPeer(peerPubkey));
		const actions = channel.handleSpliceAck(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleSpliceLockedMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeSpliceLockedMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleSpliceLocked(msg);
		this.processActions(peerPubkey, channel, actions);
		this.commitAfterSpliceIfComplete(channel);
	}

	private handleStartBatchMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeStartBatchMessage(payload);
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
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
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

		const actions = channel.abortSplice(reason);
		this.processActions(peerPubkey, channel, actions);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	// ─────────────── Dual Funding (v2) ───────────────

	/**
	 * Open a dual-funded channel (v2) with a peer.
	 *
	 * opts.trusted opens it zero-conf (see openChannel): the zero_conf channel
	 * type is added to the negotiated type and both sides fast-track
	 * channel_ready after tx_signatures. Requires the peer in the trusted set.
	 */
	createDualFundedChannel(
		peerPubkey: string,
		params: IDualFundingParams,
		opts?: { trusted?: boolean }
	): Channel {
		// FIRST, ahead of every other check: this is the pre-allocation
		// boundary. Nothing below it may run, because everything below it has
		// an effect worth undoing (a derivation index, a signer, a temp
		// channel, wallet inputs the caller reserved for the open). The
		// refusal is a throw rather than a v1 fallback: this API is
		// explicitly dual-funded and the caller may be contributing its own
		// inputs, so quietly opening something else would be answering a
		// different question than the one asked.
		if (this._quorumRefusesDualFunding()) {
			throw new Error(QUORUM_NO_DUAL_FUND_REFUSAL);
		}
		if (opts?.trusted && !this.zeroConfManager.isTrustedPeer(peerPubkey)) {
			throw new Error(
				`Peer ${peerPubkey} is not in the trusted set; add it with addTrustedPeer before a trusted open`
			);
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
		// CLN requires the channel_type TLV on open_channel2 (tx_abort: "open_channel2
		// missing channel_type"). Default it exactly like the legacy open
		// (Channel.initiateOpen): a taproot channel_type is the single
		// OPTION_TAPROOT bit — the taproot bit implies anchor-style commitments
		// and static_remotekey, and any extra bit makes peers reject the type —
		// otherwise static_remotekey plus anchors when preferred. Without the
		// taproot branch, an openChannel routed here by the peer's dual-fund
		// feature would silently open a different channel type than the same
		// call against a v1 peer.
		let channelType = params.channelType;
		if (!channelType) {
			const typeFlags = FeatureFlags.empty();
			if (this.config.preferTaproot) {
				typeFlags.setCompulsory(Feature.OPTION_TAPROOT);
			} else {
				typeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
				if (this.config.preferAnchors) {
					typeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
				}
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
			channelFlags = (channelFlags ?? 0x01) & ~0x01;
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
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);
		this.processActions(peerPubkey, channel, actions);

		this.emit('channel:opened', channel.getTemporaryChannelId());
		return channel;
	}

	private handleOpenChannel2(peerPubkey: string, payload: Buffer): void {
		const msg = decodeOpenChannel2Message(payload);

		// Quorum mode masks option_dual_fund, so a compliant peer never sends
		// this. Feature negotiation is advisory though: it can be cached,
		// raced against a mode change, or simply ignored, so the handler
		// refuses for itself, ahead of everything with an effect. It is the
		// unsupported-open path and nothing else: no keys derived, no index
		// advanced, no temp channel, no row.
		if (this._quorumRefusesDualFunding()) {
			this.emit('error', msg.channelId, QUORUM_NO_DUAL_FUND_REFUSAL);
			return;
		}

		// Reject opens for a chain we do not operate on (the v1 open path
		// applies the same guard).
		if (
			this.config.chainHash &&
			msg.chainHash &&
			!msg.chainHash.equals(this.config.chainHash)
		) {
			this.emit(
				'error',
				msg.channelId,
				`open_channel2 for unknown chain ${msg.chainHash.toString('hex')}`
			);
			return;
		}
		if (this._namespaceCannotRecordANewChannel()) {
			this.emit('error', msg.channelId, NAMESPACE_LOST_REFUSAL);
			return;
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
			if (fp?.selectSpliceInputs) {
				fp.selectSpliceInputs(requested, msg.fundingFeeratePerkw)
					.then(({ inputs, changeScript }) => {
						channel.setDualFundingContribution(
							inputs,
							changeScript,
							requested,
							msg.fundingFeeratePerkw
						);
						const actions = channel.handleOpenChannel2(msg, localParams);
						this.processActions(peerPubkey, channel, actions);
					})
					.catch((err) => {
						this.emit(
							'error',
							msg.channelId,
							`Lease contribution not funded (${
								(err as Error)?.message ?? err
							}); accepting without will_fund`
						);
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
		const msg = decodeAcceptChannel2Message(payload);
		const channel = this.tempChannels.get(msg.channelId.toString('hex'));
		if (!channel) {
			this.emit('error', null, 'Unknown channel_id in accept_channel2');
			return;
		}

		// Liquidity ads (bLIP-0051): if we requested funds and the seller answered
		// with a will_fund, verify the seller signed these exact lease terms before
		// trusting the lease. A bad signature fails the open.
		const session = channel.getDualFundingSession();
		const requestFunds = session?.getRequestFunds();
		if (msg.willFund && requestFunds) {
			const ok = verifyWillFund(
				msg.willFund.signature,
				msg.willFund.leaseRates,
				Buffer.from(peerPubkey, 'hex'),
				msg.fundingPubkey,
				requestFunds.blockheight
			);
			if (!ok) {
				this.emit('error', msg.channelId, 'Invalid will_fund signature');
				return;
			}
			this.emit('channel:lease', {
				channelId: msg.channelId,
				requestedSats: requestFunds.requestedSats,
				leaseRates: msg.willFund.leaseRates,
				sellerFundingSatoshis: msg.fundingSatoshis
			});
		}

		const actions = channel.handleAcceptChannel2(msg);
		this.processActions(peerPubkey, channel, actions);

		// Only emit channel:accepted if accept was successful (no errors)
		const hasError = actions.some((a) => a.type === ChannelActionType.ERROR);
		if (!hasError) {
			this.emit('channel:accepted', channel, peerPubkey);
			this.autoFundDualFundedOpen(channel, peerPubkey);
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
		// A max open contributes EVERY spendable UTXO (change nets out to zero
		// against the committed amount); a fixed open covers amount + fee.
		// Without the matching provider method the legacy behavior holds: the
		// embedder drives the contribution itself via addTxInput.
		const fundMax = local.fundMax === true;
		if (fundMax ? !fp?.selectMaxDualFundingInputs : !fp?.selectSpliceInputs) {
			return;
		}

		const state = channel.getFullState();
		const contributionSats = local.fundingSatoshis + (state.leaseFeeSats ?? 0n);
		const feeratePerKw = local.fundingFeeratePerkw;

		(fundMax
			? fp!.selectMaxDualFundingInputs!()
			: fp!.selectSpliceInputs!(contributionSats, feeratePerKw)
		)
			.then(({ inputs, changeScript }) => {
				channel.setDualFundingContribution(
					inputs,
					changeScript,
					contributionSats,
					feeratePerKw
				);
				const driveActions = channel.beginDualFundingContribution();
				this.processActions(peerPubkey, channel, driveActions);
			})
			.catch((err) => {
				// Unlike the lease seller, the opener cannot downgrade to a
				// zero contribution: the channel cannot exist without our
				// funding. Surface the reason and abort the negotiation so the
				// peer forgets the channel instead of waiting on us.
				this.emit(
					'error',
					channel.getChannelId() ?? channel.getTemporaryChannelId(),
					`v2 open not funded: ${(err as Error)?.message ?? err}`
				);
				const abortActions = channel.abortDualFunding(
					`opener funding unavailable: ${(err as Error)?.message ?? err}`
				);
				this.processActions(peerPubkey, channel, abortActions);
			});
	}

	private handleTxAddInput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxAddInputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddInput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAddOutput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxAddOutputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveInput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxRemoveInputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveInput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveOutput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxRemoveOutputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxCompleteMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxCompleteMessage(payload);
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
		const msg = decodeTxSignaturesMessage(payload);
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
	 * Deferred until the open reaches AWAITING_FUNDING_CONFIRMED: while the
	 * channel is still in the commitment_signed / tx_signatures round (state
	 * AWAITING_TX_SIGNATURES) it MUST stay in tempChannels so a mid-round peer
	 * disconnect is aborted by handlePeerDisconnected (which only scans
	 * tempChannels for early-state channels). Routing still works in the interim:
	 * commitment_signed is found via findChannelByChannelIdInTemp (derived id) and
	 * tx_signatures via findTempChannel (temporary id). Idempotent.
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
			st !== ChannelState.NORMAL
		) {
			return;
		}
		const permId = cid.toString('hex');
		if (this.channels.has(permId)) return;
		const tempId = channel.getTemporaryChannelId()?.toString('hex');
		if (!tempId || !this.tempChannels.has(tempId)) return;
		this.channels.set(permId, channel);
		this.channelPeers.set(permId, peerPubkey);
		this.tempChannels.delete(tempId);
	}

	private handleTxInitRbfMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxInitRbfMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxInitRbf(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAbortMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxAbortMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findChannelByChannelIdInTemp(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAbort();
		this.processActions(peerPubkey, channel, actions);
	}

	private handleAnnouncementSignaturesMsg(
		peerPubkey: string,
		payload: Buffer
	): void {
		const msg = decodeAnnouncementSignaturesMessage(payload);
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
			// so they are simply forgotten.
			for (const tempId of [...this.tempChannels.keys()]) {
				if (this.channelPeers.get(tempId) !== peerPubkey) continue;
				this.tempChannels.delete(tempId);
				this.channelPeers.delete(tempId);
			}
			this.emit('error', msg.channelId, `Remote error: ${errorText}`);
			return;
		}

		// Clean up a temp channel if this error references one the sender owns
		if (
			this.tempChannels.has(channelIdHex) &&
			this.channelPeers.get(channelIdHex) === peerPubkey
		) {
			this.tempChannels.delete(channelIdHex);
			this.channelPeers.delete(channelIdHex);
		}

		// BOLT 1: an error referencing a specific channel means fail that
		// channel, provided it belongs to the sender: a peer must not be able to
		// fail another peer's channel by quoting its id. While a tx_abort
		// exchange for a forgotten splice is pending, the peer's error is part
		// of that dance (CLN's channeld errors/restarts around it) — failing the
		// channel here would kill it right before it recovers.
		const channel = this.channels.get(channelIdHex);
		const senderOwnsIt = this.channelPeers.get(channelIdHex) === peerPubkey;
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
			const peer = this.channelPeers.get(channelId.toString('hex'));
			if (peer) return peer;
		}
		// Check temp map
		const tempId = channel.getTemporaryChannelId().toString('hex');
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

	private processActions(
		peerPubkey: string,
		channel: Channel,
		actions: ChannelAction[]
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
			this._holdBatch(channelIdHex, peerPubkey, channel, {
				actions,
				from: 0,
				frameSequence: null,
				requiresDurability: this._carriesBarrierMessage(actions, 0),
				outboxIds: []
			});
			return;
		}

		this.emit('transition:begin', channelIdHex);
		try {
			heldFrom = this._dispatchActions(
				peerPubkey,
				channel,
				actions,
				persistRequest,
				() => sendsBlocked,
				(blocked: boolean) => {
					sendsBlocked = blocked;
				},
				0,
				false,
				(): boolean =>
					this._shouldHoldBatch(
						channelIdHex,
						actions,
						persistIndex,
						persistRequest
					)
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
			this.emit('transition:end', channelIdHex);
		}
		if (heldFrom >= 0 && channelIdHex) {
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
			this.emit('transition:blocked', peerPubkey, batchChannelId);
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
		progress?: { index: number }
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
						break;
					}
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
					this.emit(
						'error',
						channel.getChannelId() ?? channel.getTemporaryChannelId(),
						action.message
					);
					// Clean up temp channel on error
					const tempId = channel.getTemporaryChannelId()?.toString('hex');
					if (tempId && this.tempChannels.has(tempId)) {
						this.tempChannels.delete(tempId);
						this.channelPeers.delete(tempId);
					}
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
					if (channel.getState() !== ChannelState.SPLICING) {
						this.emit(
							'channel:opening',
							channel.getChannelId() || channel.getTemporaryChannelId(),
							action.fundingTxid
						);
					}
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
						return index + 1;
					}
					break;
				case ChannelActionType.SPLICE_COMPLETE:
					this.emit('splice:complete', channel.getChannelId());
					break;
			}
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
	 * Quorum mode does not START dual-funded (v2) opens.
	 *
	 * What quorum promises is that once a peer has seen new channel state from
	 * us, enough remote information exists to restore that state and resume
	 * the channel. The v2 opening round cannot keep that promise past its
	 * first commitment_signed: BOLT 2 requires the opener to remember the
	 * funding transaction and resume the signature exchange through
	 * channel_reestablish.next_funding, while this implementation holds the
	 * interactive-funding session in memory alone and discards it on
	 * disconnect. Barrier-gating commitment_signed and tx_signatures keeps
	 * those messages behind quorum durability; it does NOT make the state
	 * needed to resume them durable, and the two are not the same thing.
	 *
	 * So the mode refuses the one thing it cannot honour, rather than
	 * documenting an exception to the invariant the whole phase advertises.
	 * This is about STARTING a v2 open: an established channel that was
	 * originally opened with v2 is an ordinary channel and is untouched, as
	 * are splices, which are interactive-tx but not opens.
	 */
	private _quorumRefusesDualFunding(): boolean {
		return this.config.durabilityBarrier?.enforcing === true;
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
		const progress = { index: held.from };
		// Same bracket a live batch runs in, so a monitor change caused by the
		// released actions still rides its channel's transition instead of
		// committing as a frame of its own.
		this.emit('transition:begin', channelIdHex);
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
			this.emit('transition:end', channelIdHex);
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
	 * to attribute, hold or park. What processActions WOULD add is an
	 * uncontained observer boundary in front of the commitment broadcast, and
	 * a listener must not be able to suppress the last exit a channel has.
	 * The transition pair is emitted for the same listeners, contained on both
	 * edges so it stays balanced whatever an observer does.
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
						action.paymentHash
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
					const rebuilt = mon?.rebuildSweep(
						action.output,
						action.feeRatePerVbyte
					);
					if (rebuilt) {
						// rebuildSweep returns a bitcoin.Transaction; every broadcast:tx
						// listener expects a raw Buffer. Emitting the Transaction serialized
						// to "[object Object]" and the RBF re-bump never reached the network.
						this.emit('broadcast:tx', rebuilt.toBuffer());
					}
					break;
				}
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
				// Taproot anchors are key-path spent by the local delayed privkey;
				// legacy anchors by the funding privkey.
				localFundingPrivkey: action.taprootAnchorMerkleRoot
					? this._channelTaprootAnchorPrivkey(channelId)
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
	 * Re-CPFP any anchor force-close commitment package that is still unconfirmed,
	 * bidding a higher (live) feerate so a fee spike AFTER the original broadcast
	 * cannot pin the commitment. The initial CPFP is one-shot; without this a stuck
	 * commitment blocks every second-level HTLC claim (which spends a commitment
	 * output) and an HTLC we hold the preimage for is lost to the peer's timeout.
	 *
	 * Driven by the node each block with a live feerate (the ChannelManager has no fee
	 * estimator). An entry is dropped once its monitor leaves WATCHING (the commitment
	 * confirmed, or the channel otherwise resolved).
	 *
	 * @param blockHeight - current chain tip
	 * @param feeRatePerVbyte - live force-close feerate from the node's estimator
	 */
	reCpfpStuckCommitments(blockHeight: number, feeRatePerVbyte: number): void {
		this._currentBlockHeight = blockHeight;
		for (const [channelIdHex, entry] of this._pendingCommitmentCpfp) {
			const monitor = this.monitors.get(channelIdHex);
			// Stop CPFP only once the monitor is gone, fully resolved, or our commitment
			// has CONFIRMED. Do NOT stop merely because the funding spend was DETECTED:
			// the monitor leaves WATCHING the instant our own commitment is seen in the
			// mempool (chain-watcher feeds unconfirmed spends), which is exactly when a
			// fee spike can pin the package and re-CPFP is needed. Gating on WATCHING
			// alone made this re-bump inert.
			if (
				!monitor ||
				monitor.isFullyResolved() ||
				monitor.isCommitmentConfirmed()
			) {
				this._pendingCommitmentCpfp.delete(channelIdHex);
				continue;
			}
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
