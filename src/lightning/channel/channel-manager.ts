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
import { ChannelAction, ChannelActionType } from './channel-actions';
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
	/** Chain hash for open_channel messages (defaults to Bitcoin mainnet) */
	chainHash?: Buffer;
	/** Node identity private key (for announcements) */
	nodePrivateKey?: Buffer;
	/** Per-channel key derivation callback. If provided, each new channel gets unique keys. */
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
	 */
	openChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint
	): Channel {
		// Verify peer is connected before creating channel state
		if (this.peerManager && !this.peerManager.getPeer(peerPubkey)) {
			throw new Error(`Not connected to peer ${peerPubkey}`);
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
		return { ok: true, actions };
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
		return { ok: true, actions };
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
		return { ok: true, actions };
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
		return { ok: true, actions };
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
		return { ok: true, actions };
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
	 */
	restoreChannel(
		channel: Channel,
		peerPubkey: string,
		keyIndex?: number | null
	): void {
		if (this.config.chainHash) {
			channel.announcementChainHash = this.config.chainHash;
		}
		const channelId = channel.getChannelId();
		if (channelId) {
			// Wire signer — use per-channel keys when available
			let fundingPrivkey = this.config.localFundingPrivkey;
			let htlcBasepointSecret = this.config.htlcBasepointSecret;

			if (this.config.channelKeyDeriver && keyIndex != null) {
				const perChannelKeys = this.config.channelKeyDeriver(keyIndex);
				fundingPrivkey = perChannelKeys.fundingPrivkey;
				htlcBasepointSecret = perChannelKeys.htlcBasepointSecret;
				// Preserve key index on channel for future persists
				channel.channelKeyIndex = keyIndex;
				// Advance _nextChannelIndex past any restored index
				if (keyIndex >= this._nextChannelIndex) {
					this._nextChannelIndex = keyIndex + 1;
				}
			}

			const signer = this.makeSigner(
				this.config.channelKeyDeriver && keyIndex != null ? keyIndex : 0,
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
	 */
	getRecoveryChannelMaterial(channelKeyIndex: number | null): {
		basepoints: IChannelBasepoints;
		perCommitmentSeed: Buffer;
		localConfig: IChannelConfig;
	} {
		if (this.config.channelKeyDeriver && channelKeyIndex != null) {
			const keys = this.config.channelKeyDeriver(channelKeyIndex);
			return {
				basepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG
			};
		}
		return {
			basepoints: this.config.localBasepoints,
			perCommitmentSeed: this.config.localPerCommitmentSeed,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG
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
		const actions = channel.forceClose(signer);
		const failure = actions.find(
			(a): a is { type: ChannelActionType.ERROR; message: string } =>
				a.type === ChannelActionType.ERROR
		);
		if (failure) {
			this.emit('error', channelId, failure.message);
			return { ok: false, actions, error: failure.message };
		}
		const peerPubkey = this.channelPeers.get(channelId.toString('hex'));
		if (peerPubkey) {
			this.processActions(peerPubkey, channel, actions);
		}
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
	 * Central message dispatch handler.
	 */
	handleMessage(peerPubkey: string, type: number, payload: Buffer): void {
		try {
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

		// Enable zero-conf if peer is trusted
		if (this.zeroConfManager.isTrustedPeer(peerPubkey)) {
			const channelState = channel.getFullState();
			channelState.trustedPeer = true;
			channelState.zeroConfEnabled = true;
			channelState.minimumDepth = 0;
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
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) {
			this.emit('error', msg.channelId, 'Unknown channel_id in channel_ready');
			return;
		}

		const actions = channel.handleChannelReady(msg);
		this.processActions(peerPubkey, channel, actions);
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
		this.processActions(peerPubkey, channel, actions);

		// Watchtower: on a clean revocation, hand the just-revoked remote
		// commitment tx (if we cached it) to any listener so it can ship justice
		// data to towers before the peer can broadcast the breach.
		const hadError = actions.some((a) => a.type === ChannelActionType.ERROR);
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
	 */
	createDualFundedChannel(
		peerPubkey: string,
		params: IDualFundingParams
	): Channel {
		const chKeys = this.deriveKeysForNewChannel();
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: params.fundingSatoshis,
			pushMsat: 0n,
			localConfig: this.config.localConfig || DEFAULT_CHANNEL_CONFIG,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed
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

		// The channel signs with chKeys, so it MUST advertise chKeys on the wire —
		// otherwise the funding pubkey (2-of-2) and the revocation basepoint (which
		// the v2 channel_id is derived from) would not match what the peer sees.
		// Override the caller's key material with the channel's own (mirrors the
		// acceptor path in handleOpenChannel2). In the common case (no per-channel
		// key deriver) these are already equal.
		// CLN requires the channel_type TLV on open_channel2 (tx_abort: "open_channel2
		// missing channel_type"). Default it exactly like the legacy open.
		let channelType = params.channelType;
		if (!channelType) {
			const typeFlags = FeatureFlags.empty();
			typeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			if (this.config.preferAnchors) {
				typeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			}
			channelType = typeFlags.toBuffer();
		}

		const alignedParams: IDualFundingParams = {
			...params,
			chainHash: params.chainHash ?? this.config.chainHash,
			channelType,
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
						const actions = channel.handleOpenChannel2(msg, localParams);
						this.processActions(peerPubkey, channel, actions);
					});
				return;
			}
			// No funding provider: keep the legacy behavior (the embedder — or a
			// test harness — drives the contribution itself via addTxInput).
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
		}
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
		if (channel.getState() !== ChannelState.AWAITING_FUNDING_CONFIRMED) return;
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
		this.emit('channel:persist', channelId);
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
		for (const action of actions) {
			switch (action.type) {
				case ChannelActionType.SEND_MESSAGE:
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
				case ChannelActionType.BROADCAST_TX:
					this.emit('broadcast:tx', action.tx);
					break;
				case ChannelActionType.FORCE_CLOSE:
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
					this.emit(
						'channel:persist',
						channel.getChannelId() || channel.getTemporaryChannelId()
					);
					break;
				case ChannelActionType.SPLICE_COMPLETE:
					this.emit('splice:complete', channel.getChannelId());
					break;
			}
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
