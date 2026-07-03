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
	decodeUpdateFeeMessage
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
	decodeSpliceLockedMessage
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
import { ChannelSigner } from '../keys/signer';
import {
	signRemoteCommitment,
	signRemoteCommitmentPartial,
	signRemoteHtlcSignaturesTaproot
} from './commitment-builder';
import { generateNonce } from '../crypto/musig';
import { Channel } from './channel';
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
	HtlcState,
	IHtlcEntry,
	isAnchorChannel,
	isTaprootChannel,
	REGTEST_CHAIN_HASH
} from './types';
import { decodeFforHeader, encodeFforErrorMessage } from '../ffor/messages';
import {
	FforEpochState,
	FforVariant,
	IFforEpochParams,
	IFforEpochStateData
} from '../ffor/types';
import {
	buildSettlementPackage,
	fforSettlementCheckError,
	fforSkimFeeMsat,
	fforVoucherHtlcId,
	fforVoucherSumMsat
} from '../ffor/settlement';
import { IFforTowerClient, buildTowerFetchRequest } from '../ffor/tower';
import { escapeJForOwed } from '../ffor/escape';
import { FFOR_ESCAPE_DELAY_BLOCKS } from '../ffor/types';
import { encode as encodeBolt11Invoice } from '../invoice/encode';
import { Network } from '../invoice/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../keys/derivation';
import { getPublicKey, sign } from '../crypto/ecdh';
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
import { ILeaseRates, IFforTerms } from '../gossip/types';
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
	 * Propose simple taproot channels (option_taproot). EXPERIMENTAL: the taproot
	 * commitment-round signing flow (MuSig2 nonce rotation) is not yet wired into
	 * the live state machine, so a proposed taproot channel negotiates open/accept
	 * (channel type + nonces) but cannot yet complete funding. Off by default.
	 */
	preferTaproot?: boolean;
	/** Chain hash for open_channel messages (defaults to Bitcoin mainnet) */
	chainHash?: Buffer;
	/** Node identity private key (for announcements) */
	nodePrivateKey?: Buffer;
	/** Per-channel key derivation callback. If provided, each new channel gets unique keys. */
	channelKeyDeriver?: (channelIndex: number) => IPerChannelKeys;
	/**
	 * Liquidity ads (bLIP-0051): when set, this node sells inbound liquidity at
	 * these rates — it answers a buyer's request_funds with a signed will_fund
	 * and contributes the requested funds as the acceptor.
	 */
	leaseRates?: ILeaseRates;
	/**
	 * FFOR standing terms (specs/ffor-offline-receive.md section 11.3): when
	 * set, this node advertises them alongside its lease rates (node_ann TLV
	 * 55007) and REJECTS any incoming ff_init that falls outside them.
	 */
	fforTerms?: IFforTerms;
	/**
	 * Our own advertised init features. Used to gate per-peer feature-dependent
	 * behavior (e.g. option_simple_close) on BOTH sides having advertised it.
	 * When absent, feature-gated behavior stays on the legacy path.
	 */
	localFeatures?: FeatureFlags;
}

/**
 * Manages multiple channels, dispatching messages between PeerManager
 * and Channel instances.
 *
 * Events:
 * - 'channel:opened' (channelId: Buffer)
 * - 'channel:ready' (channelId: Buffer)
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
	/**
	 * FFOR Variant B (spec §9.4): the tower client used by the settlement peer
	 * (S) to obtain a preimage release before settling a delegated payment
	 * upstream. Without it, variant-B epochs cannot settle (S has no preimage).
	 */
	private _fforTowerClient: IFforTowerClient | null = null;
	/** In-flight variant-B releases keyed by "channelIdHex:seq" (serialize). */
	private _fforPendingReleases = new Set<string>();

	constructor(config: IChannelManagerConfig) {
		super();
		this.config = config;
	}

	/**
	 * FFOR Variant B: provide the tower client S uses to request preimage
	 * releases (spec §9.4). The transport is out of scope; the client is any
	 * IFforTowerClient (in-process loopback in tests, HTTPS/onion in prod).
	 */
	setFforTowerClient(client: IFforTowerClient | null): void {
		this._fforTowerClient = client;
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
			MessageType.SHUTDOWN,
			MessageType.CLOSING_SIGNED,
			MessageType.CLOSING_COMPLETE,
			MessageType.CLOSING_SIG,
			MessageType.CHANNEL_REESTABLISH,
			MessageType.STFU,
			MessageType.SPLICE,
			MessageType.SPLICE_ACK,
			MessageType.SPLICE_LOCKED,
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
			// FFOR: Fast-Forward Offline Receive epoch setup + settlement +
			// reconciliation (specs/ffor-offline-receive.md §14)
			MessageType.FF_INIT,
			MessageType.FF_ACCEPT,
			MessageType.FF_INVOICES,
			MessageType.FF_ESCAPE_SIGS,
			MessageType.FF_BEGIN,
			MessageType.FF_SETTLEMENT,
			MessageType.FF_RECONCILE,
			MessageType.FF_RECONCILE_ACK,
			MessageType.FF_REVOKE_BATCH,
			MessageType.FF_END,
			MessageType.FF_ERROR,
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

		const signer = new ChannelSigner(
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		channel.channelKeyIndex = chKeys.channelIndex;
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

		const signer = new ChannelSigner(
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		channel.channelKeyIndex = chKeys.channelIndex;
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
			const signer =
				channel.getSigner() ||
				new ChannelSigner(
					this.config.localFundingPrivkey,
					this.config.htlcBasepointSecret
				);
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
		signer: ChannelSigner,
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
		signer: ChannelSigner,
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
			actions = channel.signCommitment(signature, htlcSignatures);
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

			const signer = new ChannelSigner(fundingPrivkey, htlcBasepointSecret);
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
				st === ChannelState.SPLICING ||
				// FFOR: an ACTIVE epoch survives restart (FF_EPOCH is restored
				// after reestablish); a restored mid-SETUP channel aborts cleanly
				// inside markForReestablish (spec §7.5/§11.1).
				st === ChannelState.FF_SETUP ||
				st === ChannelState.FF_EPOCH
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

		const signer =
			channel.getSigner() ||
			new ChannelSigner(
				this.config.localFundingPrivkey,
				this.config.htlcBasepointSecret
			);
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
				case MessageType.FF_INIT:
					this.handleFforInitMsg(peerPubkey, payload);
					break;
				case MessageType.FF_ACCEPT:
					this.handleFforAcceptMsg(peerPubkey, payload);
					break;
				case MessageType.FF_INVOICES:
					this.handleFforInvoicesMsg(peerPubkey, payload);
					break;
				case MessageType.FF_ESCAPE_SIGS:
					this.handleFforEscapeSigsMsg(peerPubkey, payload);
					break;
				case MessageType.FF_BEGIN:
					this.handleFforBeginMsg(peerPubkey, payload);
					break;
				case MessageType.FF_SETTLEMENT:
					this.handleFforSettlementMsg(peerPubkey, payload);
					break;
				case MessageType.FF_RECONCILE:
					this.handleFforReconcileMsg(peerPubkey, payload);
					break;
				case MessageType.FF_RECONCILE_ACK:
					this.handleFforReconcileAckMsg(peerPubkey, payload);
					break;
				case MessageType.FF_REVOKE_BATCH:
					this.handleFforRevokeBatchMsg(peerPubkey, payload);
					break;
				case MessageType.FF_END:
					this.handleFforEndMsg(peerPubkey, payload);
					break;
				case MessageType.FF_ERROR:
					this.handleFforErrorMsg(peerPubkey, payload);
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

		const signer = new ChannelSigner(
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		channel.channelKeyIndex = chKeys.channelIndex;
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
		const signer =
			channel.getSigner() ||
			new ChannelSigner(
				this.config.localFundingPrivkey,
				this.config.htlcBasepointSecret
			);

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
		// this does not loop. Skip if handleCommitmentSigned returned an error.
		if (!hasError && channel.getChannelId()) {
			this.autoSignAndSendCommitment(channel.getChannelId()!);
		}
	}

	private handleRevokeAndAck(peerPubkey: string, payload: Buffer): void {
		const msg = decodeRevokeAndAckMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleRevokeAndAck(msg);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: After processing revoke_and_ack, an HTLC_FORWARDED event above may
		// have triggered a local fulfill/fail (setting needsCommitment). Send
		// commitment_signed to commit those updates on the remote's side.
		// autoSignAndSendCommitment is a no-op unless we owe a commitment, so this
		// does not loop.
		const channelId = channel.getChannelId();
		if (channelId) {
			this.autoSignAndSendCommitment(channelId);
		}

		// FFOR (spec §9.2): the revoke completed a commitment round — any inbound
		// HTLC on this channel is now irrevocably committed; settle it if its
		// hash belongs to an active epoch's delegated set.
		this._fforProcessSettlements(channel);
	}

	private handleUpdateFeeMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeUpdateFeeMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleUpdateFee(msg);
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
		const actions = channel.handleShutdown(msg, defaultScript);
		this.processActions(peerPubkey, channel, actions);

		if (channel.getState() !== ChannelState.NEGOTIATING_CLOSING) return;

		if (channel.isSimpleClose()) {
			// option_simple_close: BOTH sides SHOULD send closing_complete.
			this.startSimpleClose(peerPubkey, channel);
			return;
		}

		// BOLT 2: opener must send first closing_signed after both shutdowns exchanged
		if (channel.getRole() === ChannelRole.OPENER) {
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
			const closeTx = this.buildSignedMutualCloseTx(
				channel,
				msg.feeSatoshis,
				msg.signature
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
			const { tx, witnessScript, fundingSatoshis, remoteFundingPubkey } =
				this.buildClosingTxAndScript(channel, feeSatoshis);
			const signer =
				channel.getSigner() ||
				new ChannelSigner(this.config.localFundingPrivkey);
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
			feeAmount: feeSatoshis
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
		const { tx, witnessScript, fundingSatoshis } = this.buildClosingTxAndScript(
			channel,
			feeSatoshis
		);
		const signer =
			channel.getSigner() || new ChannelSigner(this.config.localFundingPrivkey);
		return signer.signClosingTx(tx, witnessScript, Number(fundingSatoshis));
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
		const {
			tx,
			witnessScript,
			fundingSatoshis,
			localFundingPubkey,
			remoteFundingPubkey
		} = this.buildClosingTxAndScript(channel, feeSatoshis);
		const signer =
			channel.getSigner() || new ChannelSigner(this.config.localFundingPrivkey);
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

	// ─────────────── option_simple_close ───────────────

	/**
	 * Kick off (or restart) the simple-close signing flow: send our
	 * closing_complete as closer. Both sides do this independently; each
	 * side's fee comes out of its own output. Skipped when our balance can't
	 * cover a relayable fee — we then simply act as closee for the peer's
	 * closing_complete.
	 */
	private startSimpleClose(peerPubkey: string, channel: Channel): void {
		const { estimateSimpleCloseFee } = require('../chain/closing');
		const state = channel.getFullState();
		const localScript = state.localShutdownScript;
		const remoteScript = state.remoteShutdownScript;
		if (!localScript || localScript.length === 0 || !remoteScript) return;

		const feeratePerKw = state.localConfig.feeratePerKw || 253;
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
		const signer =
			channel.getSigner() || new ChannelSigner(this.config.localFundingPrivkey);
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
			const signer =
				channel.getSigner() ||
				new ChannelSigner(this.config.localFundingPrivkey);
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
			const signer =
				channel.getSigner() ||
				new ChannelSigner(this.config.localFundingPrivkey);
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
			this.sendMessage(
				peerPubkey,
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: msg.channelId,
					data: Buffer.from('unknown or closed channel', 'utf8')
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
				this.sendMessage(
					peerPubkey,
					MessageType.SHUTDOWN,
					encodeShutdownMessage({
						channelId: fullState.channelId!,
						scriptPubkey: fullState.localShutdownScript
					})
				);
			}
			if (state === ChannelState.NEGOTIATING_CLOSING) {
				if (channel.isSimpleClose()) {
					// Both roles restart the simple-close signing flow.
					this.startSimpleClose(peerPubkey, channel);
				} else if (channel.getRole() === ChannelRole.OPENER) {
					// Opener re-proposes closing_signed to resume fee negotiation
					const closingActions = channel.proposeClosingFee(
						(feeSatoshis: bigint) => this.signClosingTx(channel, feeSatoshis)
					);
					this.processActions(peerPubkey, channel, closingActions);
				}
			}
		}

		// FFOR (spec §11.1): with the channel back in FF_EPOCH after reestablish,
		// the settlement peer starts reconciliation by replaying its packages
		// (fforStartReplay is a no-op on the recipient / with no settlements).
		if (channel.getState() === ChannelState.FF_EPOCH) {
			const replay = channel.fforStartReplay();
			if (replay.length > 0) {
				this.processActions(peerPubkey, channel, replay);
			}
		}

		// FFOR (spec §9.2 crash replay): an upstream channel restored with a
		// still-committed delegated HTLC re-runs the settlement engine — the
		// persisted package makes this idempotent by seq.
		this._fforProcessSettlements(channel);
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

		const actions = channel.handleSplice(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleSpliceAckMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeSpliceAckMessage(payload);
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

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

	// ─────────────── FFOR: Fast-Forward Offline Receive ───────────────
	// specs/ffor-offline-receive.md — M1: epoch establishment.

	/**
	 * Whether the peer's init features negotiated FFOR. Requires BOTH
	 * option_quiesce (setup runs from quiescence, spec §5) and
	 * option_ff_receive (560/561). Like peerSupportsSplicing, an unknown peer
	 * init defaults to true (unit tests drive managers directly).
	 */
	private peerSupportsFfor(peerPubkey: string): boolean {
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		if (!init) return true;
		return (
			init.features.hasFeature(Feature.QUIESCE) &&
			init.features.hasFeature(Feature.OPTION_FF_RECEIVE)
		);
	}

	/** Peer node id + node-key signer handed to the channel's FFOR handlers. */
	private _fforExtras(peerPubkey: string): {
		remoteNodeId: Buffer;
		signFn?: (digest: Buffer) => Buffer;
		fforTerms?: IFforTerms;
	} {
		const nodeKey = this.config.nodePrivateKey;
		return {
			remoteNodeId: Buffer.from(peerPubkey, 'hex'),
			signFn: nodeKey
				? (digest: Buffer): Buffer => sign(digest, nodeKey)
				: undefined,
			// §11.3: when WE advertise standing FFOR terms, an incoming ff_init
			// must fall within them (checked by FforEpoch.acceptInit).
			fforTerms: this.config.fforTerms
		};
	}

	/**
	 * Default builder for the epoch's K amountless BOLT 11 invoices (spec
	 * §7.3): payment hash H_i, no amount, expiry covering a wall-clock estimate
	 * of T_exp, a route hint S→R when the channel has an SCID, signed by OUR
	 * node key. Returns undefined when no node key is configured.
	 */
	private _defaultFforInvoiceFactory(
		channel: Channel,
		peerPubkey: string
	): ((paymentHashes: Buffer[]) => string[]) | undefined {
		const nodeKey = this.config.nodePrivateKey;
		if (!nodeKey) return undefined;
		return (paymentHashes: Buffer[]): string[] => {
			const network = this.config.chainHash?.equals(REGTEST_CHAIN_HASH)
				? Network.REGTEST
				: Network.MAINNET;
			const ffor = channel.getFforEpoch();
			const st = channel.getFullState();
			const scid = st.scidAlias ?? st.shortChannelId;
			// Spec §7.3: invoice expiry ≥ wall-clock estimate of T_exp
			// (~10 min/block); fall back to 60 days when the tip is unknown.
			const tExp = ffor?.params.voucherExpiry ?? 0;
			const expiry =
				this._currentBlockHeight > 0 && tExp > this._currentBlockHeight
					? Math.max(3600, (tExp - this._currentBlockHeight) * 600)
					: 60 * 24 * 3600;
			return paymentHashes.map((h) =>
				encodeBolt11Invoice({
					network,
					paymentHash: h,
					description: 'ffor',
					expiry,
					...(scid
						? {
								routingHints: [
									[
										{
											pubkey: Buffer.from(peerPubkey, 'hex'),
											shortChannelId: scid,
											feeBaseMsat: ffor?.params.feeBaseMsat ?? 0,
											feeProportionalMillionths:
												ffor?.params.feeProportionalMillionths ?? 0,
											cltvExpiryDelta: 144
										}
									]
								]
						  }
						: {}),
					privateKey: nodeKey
				})
			);
		};
	}

	/**
	 * R side: open a fast-forward epoch on a channel (spec §7). Requires a
	 * configured node private key (ff_init/ff_accept are node-key signed).
	 */
	initiateFforEpoch(
		channelId: Buffer,
		params: Omit<IFforEpochParams, 'rPerCommitmentPoints'> & {
			rPerCommitmentPoints?: Buffer[];
		},
		options?: {
			epochId?: Buffer;
			invoiceFactory?: (paymentHashes: Buffer[]) => string[];
		}
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
		const extras = this._fforExtras(peerPubkey);
		if (!extras.signFn) {
			const error = 'FFOR requires a node private key (signed setup messages)';
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const invoiceFactory =
			options?.invoiceFactory ??
			this._defaultFforInvoiceFactory(channel, peerPubkey);
		const actions = channel.initiateFforEpoch(params, {
			signFn: extras.signFn,
			remoteNodeId: extras.remoteNodeId,
			epochId: options?.epochId,
			invoiceFactory
		});
		this.processActions(peerPubkey, channel, actions);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	/** Either side: cooperatively close a zero-settlement epoch via ff_end. */
	endFforEpoch(channelId: Buffer): ChannelResult {
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
		const actions = channel.endFforEpoch();
		this.processActions(peerPubkey, channel, actions);
		return {
			ok: !actions.some((a) => a.type === ChannelActionType.ERROR),
			actions
		};
	}

	private handleFforInitMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId, epochId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		// Reject ff_init from a peer that never negotiated option_ff_receive.
		if (!this.peerSupportsFfor(peerPubkey)) {
			this.sendMessage(
				peerPubkey,
				MessageType.FF_ERROR,
				encodeFforErrorMessage({
					channelId,
					epochId,
					data: Buffer.from('option_ff_receive not negotiated', 'utf8')
				})
			);
			this.emit(
				'error',
				channelId,
				'ff_init from peer without option_ff_receive/option_quiesce'
			);
			return;
		}

		const actions = channel.handleFforInit(
			payload,
			this._fforExtras(peerPubkey)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforAcceptMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforAccept(payload, {
			...this._fforExtras(peerPubkey),
			invoiceFactory: this._defaultFforInvoiceFactory(channel, peerPubkey)
		});
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforInvoicesMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforInvoices(
			payload,
			this._fforExtras(peerPubkey)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforEscapeSigsMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforEscapeSigs(
			payload,
			this._fforExtras(peerPubkey)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforBeginMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforBegin(
			payload,
			this._fforExtras(peerPubkey)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforEndMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforEnd(payload);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforErrorMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforError(payload);
		this.processActions(peerPubkey, channel, actions);

		// Spec §11.1: during EPOCH/RECONCILE the channel falls back to ON-CHAIN
		// enforcement rather than aborting — for the recipient that means
		// force-closing its adopted C_j^R (M3). The settlement peer MUST NOT
		// broadcast anything (§9.3: its only signed state is revoked), so no
		// fallback fires on that side. Requires a configured wallet destination
		// script; without one we surface the instruction instead of guessing a
		// sweep destination.
		const epoch = channel.getFforEpoch();
		if (
			channel.getState() === ChannelState.FF_EPOCH &&
			epoch &&
			epoch.role === 'recipient' &&
			(epoch.state === FforEpochState.FF_EPOCH ||
				epoch.state === FforEpochState.FF_RECONCILE)
		) {
			if (this._walletDestinationScript) {
				this.fforForceClose(channelId, this._walletDestinationScript);
			} else {
				this.emit(
					'error',
					channelId,
					'FFOR: ff_error during the epoch requires on-chain enforcement; call fforForceClose with a destination script'
				);
			}
		}
	}

	/**
	 * R side, on-chain enforcement (M3, spec §11.1 step 6 / §12.1): force-close
	 * with the adopted voucher commitment C_j^R. Works both post-reconciliation
	 * (S stalls voucher conversion) and straight from FF_EPOCH after package
	 * replay (S refuses to reconcile) — the packages are the counterparty
	 * signatures. Feeds every package preimage to the chain monitors so each
	 * voucher's HTLC-success claim is buildable.
	 */
	fforForceClose(
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
		const epoch = channel.getFforEpoch();
		if (epoch && epoch.role === 'recipient') {
			const prepErr = channel.fforPrepareForceClose();
			if (prepErr) {
				this.emit('error', channelId, `FFOR force-close: ${prepErr}`);
				return { ok: false, actions: [], error: prepErr };
			}
			// Voucher preimages (from the validated packages) let the monitor
			// build each HTLC-success claim; recordPreimage seeds every monitor,
			// including the one forceClose() is about to create.
			for (let k = 0; k < epoch.lastSeq; k++) {
				const preimage = epoch.preimages[k];
				if (preimage && preimage.length === 32) {
					this.recordPreimage(epoch.params.paymentHashes![k], preimage);
				}
			}
			this.emit('channel:persist', channelId);
		}
		return this.forceClose(
			channelId,
			destinationScript,
			feeRatePerVbyte,
			network
		);
	}

	/**
	 * S side, escape broadcast (spec §10, Appendix B): broadcast the correct
	 * escape E_j when R never returns. Permitted ONLY when
	 * `current height > D + escape_delay` AND reconciliation has not begun. j is
	 * chosen as ceil(owed/G), rounding UP so S bears the rounding cost. Emits
	 * the fully-witnessed E_j via broadcast:tx and returns its hex.
	 */
	fforBroadcastEscape(
		channelId: Buffer,
		currentBlockHeight: number,
		escapeDelay = FFOR_ESCAPE_DELAY_BLOCKS
	): {
		ok: boolean;
		error?: string;
		txHex?: string;
		j?: number;
		voucherValueSat?: bigint;
	} {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			return { ok: false, error: `Channel not found: ${idHex}` };
		}
		const epoch = channel.getFforEpoch();
		if (!epoch || epoch.role !== 'settlement_peer') {
			return { ok: false, error: 'no settlement-peer FFOR epoch' };
		}
		if (epoch.params.escapeGranularityMsat <= 0n) {
			return { ok: false, error: 'epoch has no escapes (G = 0)' };
		}
		// Precondition 1 (§10): reconciliation must NOT have begun. Once the
		// epoch is reconciling/closed, S has revealed (or will reveal) the n0+1
		// secret and any escape is a penalizable revoked state.
		if (epoch.state !== FforEpochState.FF_EPOCH) {
			return {
				ok: false,
				error: `cannot escape after reconciliation began (epoch state ${epoch.state})`
			};
		}
		// Precondition 2 (§10): height > D + escape_delay.
		const threshold = epoch.params.settlementDeadline + escapeDelay;
		if (currentBlockHeight <= threshold) {
			return {
				ok: false,
				error: `escape not permitted until height > D + escape_delay (${threshold}); current ${currentBlockHeight}`
			};
		}
		// owed = Σ v_k over settled seqs; j = ceil(owed/G), rounding UP.
		const owedMsat = fforVoucherSumMsat(epoch, epoch.lastSeq);
		const j = escapeJForOwed(owedMsat, epoch.params.escapeGranularityMsat);
		if (j < 1) {
			return {
				ok: false,
				error: 'nothing owed (owed = 0): no escape needed'
			};
		}
		const built = channel.fforBuildEscapeForBroadcast(j);
		if (!built.ok || !built.txHex) {
			this.emit('error', channelId, `FFOR escape: ${built.error}`);
			return { ok: false, error: built.error };
		}
		this.emit('broadcast:tx', Buffer.from(built.txHex, 'hex'));
		return {
			ok: true,
			txHex: built.txHex,
			j,
			voucherValueSat: built.voucherValueSat
		};
	}

	/**
	 * R side, escape-voucher claim (spec §10 path 3): claim the aggregate
	 * voucher of a broadcast E_j to R's wallet, using R's static payment
	 * basepoint secret (seed-derivable, no epoch data needed for the key).
	 */
	fforClaimEscapeVoucher(
		channelId: Buffer,
		escapeTxHex: string,
		destinationScript: Buffer,
		feeSatoshis?: bigint
	): { ok: boolean; error?: string; txHex?: string } {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			return { ok: false, error: `Channel not found: ${idHex}` };
		}
		const perCh = this.perChannelMonitorKeys(channel);
		const rPaymentSecret =
			perCh?.paymentBasepointSecret ?? this.config.paymentBasepointSecret;
		if (!rPaymentSecret) {
			return { ok: false, error: 'no payment basepoint secret for R claim' };
		}
		const res = channel.fforClaimEscapeVoucher(
			escapeTxHex,
			destinationScript,
			rPaymentSecret,
			feeSatoshis
		);
		if (res.ok && res.txHex) {
			this.emit('broadcast:tx', Buffer.from(res.txHex, 'hex'));
		}
		return res;
	}

	/**
	 * R side, stale-escape penalty (spec §B.5 / §12.1): after full
	 * reconciliation, penalize a broadcast E_j by claiming its aggregate
	 * voucher via revocation path 1 (the to_local/to_remote are swept by the
	 * standard revoked-commitment monitor path). Needs R's revocation basepoint
	 * secret; the n0+1 secret is already in R's shachain from reconciliation.
	 */
	fforPenalizeStaleEscape(
		channelId: Buffer,
		escapeTxHex: string,
		destinationScript: Buffer,
		feeSatoshis?: bigint
	): { ok: boolean; error?: string; txHex?: string } {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			return { ok: false, error: `Channel not found: ${idHex}` };
		}
		const perCh = this.perChannelMonitorKeys(channel);
		const revSecret =
			perCh?.revocationBasepointSecret ?? this.config.revocationBasepointSecret;
		if (!revSecret) {
			return { ok: false, error: 'no revocation basepoint secret for penalty' };
		}
		const res = channel.fforPenalizeEscapeVoucher(
			escapeTxHex,
			destinationScript,
			revSecret,
			feeSatoshis
		);
		if (res.ok && res.txHex) {
			this.emit('broadcast:tx', Buffer.from(res.txHex, 'hex'));
		}
		return res;
	}

	/**
	 * R side, Variant B recovery (spec §9.4/§11.1): fetch all packages +
	 * preimages from the tower and ingest them into the epoch (validated with
	 * the §9.4 checklist). Used when S has vanished — the tower is R's
	 * independent copy. On success the channel is ready for fforForceClose().
	 * Requires the node private key (the fetch is authenticated by R's node
	 * key). `crossCheck` optionally passes S's replayed packages for the
	 * discrepancy check (§12.2) when S is present.
	 */
	async fforRecoverFromTower(
		channelId: Buffer,
		tower: IFforTowerClient,
		crossCheck?: Buffer[]
	): Promise<ChannelResult> {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const epoch = channel.getFforEpoch();
		if (!epoch || epoch.role !== 'recipient') {
			const error = 'No recipient FFOR epoch on this channel';
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const nodeKey = this.config.nodePrivateKey;
		if (!nodeKey) {
			const error = 'FFOR tower recovery requires a node private key';
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		let resp;
		try {
			resp = await tower.fetch(buildTowerFetchRequest(epoch.epochId, nodeKey));
		} catch (err) {
			const error = `tower fetch failed: ${
				err instanceof Error ? err.message : String(err)
			}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		if (!resp.ok) {
			const error = `tower fetch rejected: ${resp.error}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const ingest = channel.fforIngestTowerPackages(
			resp.packages,
			resp.preimages,
			undefined,
			crossCheck
		);
		if (!ingest.ok) {
			this.emit('error', channelId, `tower recovery: ${ingest.error}`);
			return { ok: false, actions: [], error: ingest.error };
		}
		this.emit('channel:persist', channelId);
		return { ok: true, actions: [] };
	}

	private handleFforSettlementMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforSettlement(
			payload,
			this._fforExtras(peerPubkey)
		);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforReconcileMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforReconcile(payload);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforReconcileAckMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforReconcileAck(payload);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleFforRevokeBatchMsg(peerPubkey: string, payload: Buffer): void {
		const { channelId } = decodeFforHeader(payload);
		const channel = this.findChannelByChannelId(channelId);
		if (!channel) return;

		const actions = channel.handleFforRevokeBatch(payload);
		this.processActions(peerPubkey, channel, actions);
	}

	// ─────────── FFOR M2: the S-side settlement engine (spec §9.2) ───────────

	/**
	 * Scan a channel's irrevocably-committed inbound HTLCs for delegated
	 * payments (payment_hash ∈ an active epoch's hash set, matched on the HTLC
	 * itself — the inner onion is undecryptable and discarded, §7.3) and settle
	 * them. Runs after every revoke_and_ack (the HTLC is then committed on both
	 * sides) and after reestablish (crash replay). Strictly serial by design —
	 * the scan itself is synchronous and packages are keyed by seq.
	 */
	private _fforProcessSettlements(upstreamChannel: Channel): void {
		if (upstreamChannel.getState() !== ChannelState.NORMAL) return;
		const upstreamState = upstreamChannel.getFullState();
		for (const entry of [...upstreamState.htlcs.values()]) {
			if (
				entry.direction !== HtlcDirection.RECEIVED ||
				entry.state !== HtlcState.COMMITTED
			) {
				continue;
			}
			for (const epochChannel of this.channels.values()) {
				if (epochChannel === upstreamChannel) continue;
				const epoch = epochChannel.getFforEpoch();
				if (
					!epoch ||
					epoch.role !== 'settlement_peer' ||
					epoch.state !== FforEpochState.FF_EPOCH
				) {
					continue;
				}
				const idx = (epoch.params.paymentHashes ?? []).findIndex((h) =>
					h.equals(entry.paymentHash)
				);
				if (idx < 0) continue;
				if (epoch.params.variant === FforVariant.A) {
					this._fforSettleDelegated(
						upstreamChannel,
						entry,
						epochChannel,
						epoch,
						idx
					);
				} else {
					// Variant B (spec §9.2/§9.4): the preimage release is gated by
					// the tower. Fire-and-forget (like the anchor fee-bump path);
					// serialized per seq so a re-scan does not double-dispatch.
					void this._fforSettleDelegatedViaTower(
						upstreamChannel,
						entry,
						epochChannel,
						epoch,
						idx
					);
				}
				break;
			}
		}
	}

	/** Fail a delegated HTLC upstream (spec §8: MUST NOT settle). */
	private _fforFailUpstream(
		upstreamChannel: Channel,
		htlcId: bigint,
		reason: string
	): void {
		this.emit('error', upstreamChannel.getChannelId(), `FFOR: ${reason}`);
		// NOTE: a spec-complete implementation wraps temporary_node_failure in
		// the BOLT 4 failure onion for the OUTER shared secret; onion machinery
		// lives at the node layer, so the manager sends an opaque reason.
		this.failHtlc(
			upstreamChannel.getChannelId()!,
			htlcId,
			Buffer.from('temporary_node_failure', 'utf8')
		);
	}

	/**
	 * Variant A settlement (spec §9.2): after the §8 checks pass — build the
	 * settlement package for C_i^R, persist it durably, THEN settle upstream
	 * with update_fulfill_htlc(P_i). Idempotent by seq for crash replay.
	 */
	private _fforSettleDelegated(
		upstreamChannel: Channel,
		htlc: IHtlcEntry,
		epochChannel: Channel,
		epoch: IFforEpochStateData,
		hashIndex: number
	): void {
		const epochChannelId = epochChannel.getChannelId()!;
		const seq = hashIndex + 1;

		// Already-settled hash: replay the fulfill if it never went out (crash
		// between package-persist and upstream settle), else fail the duplicate
		// part (§11.2: never settle a consumed hash again; v1 is single-part).
		if (seq <= epoch.lastSeq) {
			if (epoch.upstreamFulfilled[hashIndex]) {
				// The upstreamFulfilled flag can outlive a crash that killed the
				// fulfill round itself (the flag persists on the epoch channel;
				// the fulfill on the upstream channel). If this is the SAME
				// upstream HTLC we settled (same id, still live), re-fulfill —
				// idempotent recovery, never a duplicate credit (the package
				// already exists). Only a DIFFERENT htlc id on a consumed hash
				// is a true duplicate part (§11.2).
				if (epoch.upstreamHtlcIds[hashIndex] === htlc.id) {
					this.fulfillHtlc(
						upstreamChannel.getChannelId()!,
						htlc.id,
						epoch.preimages[hashIndex]
					);
					return;
				}
				this._fforFailUpstream(
					upstreamChannel,
					htlc.id,
					`duplicate delegated payment for consumed hash H_${seq}`
				);
				return;
			}
			this.fulfillHtlc(
				upstreamChannel.getChannelId()!,
				htlc.id,
				epoch.preimages[hashIndex]
			);
			epoch.upstreamFulfilled[hashIndex] = true;
			epoch.upstreamHtlcIds[hashIndex] = htlc.id;
			this.emit('channel:persist', epochChannelId);
			return;
		}

		// §9.1: packages are strictly sequential — the spec's hash set is
		// ordered and H_seq must be consumed as payment seq (spec erratum: §7.3
		// "serve in any order" conflicts; in-order consumption is enforced).
		if (seq !== epoch.lastSeq + 1) {
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				`out-of-order delegated payment: hash H_${seq} before H_${
					epoch.lastSeq + 1
				}`
			);
			return;
		}

		// §8 checks.
		const checkErr = fforSettlementCheckError(
			epochChannel.getFullState(),
			epoch,
			seq,
			htlc.amountMsat,
			htlc.cltvExpiry,
			this._currentBlockHeight
		);
		if (checkErr) {
			this._fforFailUpstream(upstreamChannel, htlc.id, checkErr);
			return;
		}

		const signer = epochChannel.getSigner();
		const nodeKey = this.config.nodePrivateKey;
		if (!signer || !nodeKey) {
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				'no signer/node key for settlement package'
			);
			return;
		}

		// Build + persist the package BEFORE settling upstream (§9.2 step 1).
		epoch.htlcAmountsMsat[hashIndex] = htlc.amountMsat;
		epoch.voucherAmountsMsat[hashIndex] =
			htlc.amountMsat - fforSkimFeeMsat(epoch, htlc.amountMsat);
		const { payload } = buildSettlementPackage({
			base: epochChannel.getFullState(),
			signer,
			epoch,
			channelId: epochChannelId,
			seq,
			signFn: (digest: Buffer): Buffer => sign(digest, nodeKey)
		});
		epoch.packages[hashIndex] = payload;
		epoch.lastSeq = seq;
		this.emit('channel:persist', epochChannelId);

		// §9.2 step 2: settle upstream with update_fulfill_htlc(P_i). For seq 1
		// the preimage IS per_commitment_secret_S[n0] — the upstream claim is
		// itself the revocation of our only signed commitment (§12.1).
		this.fulfillHtlc(
			upstreamChannel.getChannelId()!,
			htlc.id,
			epoch.preimages[hashIndex]
		);
		epoch.upstreamFulfilled[hashIndex] = true;
		epoch.upstreamHtlcIds[hashIndex] = htlc.id;
		this.emit('channel:persist', epochChannelId);
	}

	/**
	 * Variant B settlement (spec §9.2/§9.4): build the package, persist it, send
	 * it to the tower, and settle upstream ONLY after ff_release returns the
	 * preimage. A tower rejection or the absence of a client means S has no
	 * preimage and MUST fail the payment upstream. Idempotent by seq: a re-scan
	 * after an S crash re-requests the release (the tower is idempotent) and
	 * fulfills once the preimage is back.
	 */
	private async _fforSettleDelegatedViaTower(
		upstreamChannel: Channel,
		htlc: IHtlcEntry,
		epochChannel: Channel,
		epoch: IFforEpochStateData,
		hashIndex: number
	): Promise<void> {
		const epochChannelId = epochChannel.getChannelId()!;
		const seq = hashIndex + 1;
		const releaseKey = `${epochChannelId.toString('hex')}:${seq}`;
		if (this._fforPendingReleases.has(releaseKey)) return;

		// Already released: fulfill upstream if it never went out (crash between
		// tower release and upstream settle), else fail the duplicate part.
		if (seq <= epoch.lastSeq) {
			if (epoch.upstreamFulfilled[hashIndex]) {
				// Same-id crash replay vs true duplicate part — see the variant A
				// branch for the rationale.
				if (
					epoch.upstreamHtlcIds[hashIndex] === htlc.id &&
					epoch.preimages[hashIndex]?.length === 32
				) {
					this.fulfillHtlc(
						upstreamChannel.getChannelId()!,
						htlc.id,
						epoch.preimages[hashIndex]
					);
					return;
				}
				this._fforFailUpstream(
					upstreamChannel,
					htlc.id,
					`duplicate delegated payment for consumed hash H_${seq}`
				);
				return;
			}
			const preimage = epoch.preimages[hashIndex];
			if (preimage && preimage.length === 32) {
				this.fulfillHtlc(upstreamChannel.getChannelId()!, htlc.id, preimage);
				epoch.upstreamFulfilled[hashIndex] = true;
				epoch.upstreamHtlcIds[hashIndex] = htlc.id;
				this.emit('channel:persist', epochChannelId);
				return;
			}
			// Package released at the tower but the preimage was lost (crash before
			// storing it) — re-request below.
		} else if (seq !== epoch.lastSeq + 1) {
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				`out-of-order delegated payment: hash H_${seq} before H_${
					epoch.lastSeq + 1
				}`
			);
			return;
		}

		const tower = this._fforTowerClient;
		if (!tower) {
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				'variant B settlement requires a tower client (none configured)'
			);
			return;
		}
		const signer = epochChannel.getSigner();
		const nodeKey = this.config.nodePrivateKey;
		if (!signer || !nodeKey) {
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				'no signer/node key for settlement package'
			);
			return;
		}

		this._fforPendingReleases.add(releaseKey);
		try {
			// New package: run §8 checks, then build + PERSIST it before asking
			// the tower (mirrors §9.2 ordering: S commits the package first).
			let payload: Buffer;
			if (seq > epoch.lastSeq) {
				const checkErr = fforSettlementCheckError(
					epochChannel.getFullState(),
					epoch,
					seq,
					htlc.amountMsat,
					htlc.cltvExpiry,
					this._currentBlockHeight
				);
				if (checkErr) {
					this._fforFailUpstream(upstreamChannel, htlc.id, checkErr);
					return;
				}
				epoch.htlcAmountsMsat[hashIndex] = htlc.amountMsat;
				epoch.voucherAmountsMsat[hashIndex] =
					htlc.amountMsat - fforSkimFeeMsat(epoch, htlc.amountMsat);
				const built = buildSettlementPackage({
					base: epochChannel.getFullState(),
					signer,
					epoch,
					channelId: epochChannelId,
					seq,
					signFn: (digest: Buffer): Buffer => sign(digest, nodeKey)
				});
				payload = built.payload;
				epoch.packages[hashIndex] = payload;
				epoch.lastSeq = seq;
				this.emit('channel:persist', epochChannelId);
			} else {
				// Re-request an already-built package (crash replay).
				payload = epoch.packages[hashIndex];
			}

			const release = await tower.requestRelease(payload);
			if (!release.ok) {
				// The tower refused: S has no preimage, so it MUST fail upstream
				// (spec §9.4 / §11.4). The persisted package stays for audit; the
				// hash is marked consumed so the failed part is not retried into a
				// second tower round.
				this._fforFailUpstream(
					upstreamChannel,
					htlc.id,
					`tower rejected settlement ${seq}: ${release.error}`
				);
				return;
			}
			// Store the released preimage durably, THEN settle upstream.
			epoch.preimages[hashIndex] = Buffer.from(release.preimage);
			this.emit('channel:persist', epochChannelId);
			this.fulfillHtlc(
				upstreamChannel.getChannelId()!,
				htlc.id,
				release.preimage
			);
			epoch.upstreamFulfilled[hashIndex] = true;
			epoch.upstreamHtlcIds[hashIndex] = htlc.id;
			this.emit('channel:persist', epochChannelId);
		} catch (err) {
			// A transport failure/timeout leaves S without the preimage: fail
			// the payment upstream (spec §11.4). The persisted package lets a
			// later retry re-request the (idempotent) release.
			this._fforFailUpstream(
				upstreamChannel,
				htlc.id,
				`tower release failed for settlement ${seq}: ${
					err instanceof Error ? err.message : String(err)
				}`
			);
		} finally {
			this._fforPendingReleases.delete(releaseKey);
		}
	}

	/**
	 * R side, §11.1 step 6: convert the reconciled vouchers to plain balance by
	 * fulfilling each with its package preimage through the stock commitment
	 * dance. Call after ff_end returns the channel to NORMAL.
	 */
	fforFulfillVouchers(channelId: Buffer): ChannelResult {
		const idHex = channelId.toString('hex');
		const channel = this.channels.get(idHex);
		if (!channel) {
			const error = `Channel not found: ${idHex}`;
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		const epoch = channel.getFforEpoch();
		if (!epoch || epoch.role !== 'recipient') {
			const error = 'No reconciled FFOR epoch on this channel';
			this.emit('error', channelId, error);
			return { ok: false, actions: [], error };
		}
		for (let k = 1; k <= epoch.lastSeq; k++) {
			const preimage = epoch.preimages[k - 1];
			if (!preimage || preimage.length !== 32) continue;
			this.fulfillHtlc(channelId, fforVoucherHtlcId(epoch, k), preimage);
		}
		return { ok: true, actions: [] };
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

		const signer = new ChannelSigner(
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		channel.channelKeyIndex = chKeys.channelIndex;

		// The channel signs with chKeys, so it MUST advertise chKeys on the wire —
		// otherwise the funding pubkey (2-of-2) and the revocation basepoint (which
		// the v2 channel_id is derived from) would not match what the peer sees.
		// Override the caller's key material with the channel's own (mirrors the
		// acceptor path in handleOpenChannel2). In the common case (no per-channel
		// key deriver) these are already equal.
		const alignedParams: IDualFundingParams = {
			...params,
			localBasepoints: chKeys.basepoints,
			localPerCommitmentSeed: chKeys.perCommitmentSeed,
			secondPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(chKeys.perCommitmentSeed, 0xffffffffffffn - 1n)
			)
		};

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

		const signer = new ChannelSigner(
			chKeys.fundingPrivkey,
			chKeys.htlcBasepointSecret
		);
		const channel = new Channel(state, signer);
		channel.channelKeyIndex = chKeys.channelIndex;
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
				msg.channelType,
				this.config.leaseRates,
				this.config.nodePrivateKey
			);
			localParams.willFund = { signature, leaseRates: this.config.leaseRates };
			localParams.fundingSatoshis = msg.requestFunds.requestedSats;
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
				requestFunds.blockheight,
				// Verify over the channel_type WE proposed in open_channel2 (what the
				// seller signed), not the accept's echo, which the v2 flow may omit.
				session?.getOpenChannelType()
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
	}

	private handleErrorMsg(_peerPubkey: string, payload: Buffer): void {
		const msg = decodeErrorMessage(payload);
		const channelIdHex = msg.channelId.toString('hex');

		// Clean up temp channel if this error references one
		if (this.tempChannels.has(channelIdHex)) {
			this.tempChannels.delete(channelIdHex);
			this.channelPeers.delete(channelIdHex);
		}

		// BOLT 1: an error referencing a specific channel means fail that channel.
		// Mark it ERRORED so we stop sending channel_reestablish for it on every
		// reconnect (which the peer just rejects again → disconnect storm). An
		// all-zeroes channel_id is a connection-level error, not channel-specific,
		// so we leave channels untouched in that case.
		const isConnectionWide =
			msg.channelId.length === 0 || msg.channelId.every((b) => b === 0);
		const channel = this.channels.get(channelIdHex);
		// While a tx_abort exchange for a forgotten splice is pending, the peer's
		// error is part of that dance (CLN's channeld errors/restarts around it) —
		// failing the channel here would kill it right before it recovers.
		const inAbortDance = channel?.isSpliceAbortPending() ?? false;
		if (
			!isConnectionWide &&
			channel &&
			!inAbortDance &&
			channel.markErrored()
		) {
			this.emit('channel:persist', channel.getChannelId() || msg.channelId);
		}

		const errorText = msg.data.toString('utf8');
		this.emit('error', msg.channelId, `Remote error: ${errorText}`);
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
		for (const action of actions) {
			switch (action.type) {
				case ChannelActionType.SEND_MESSAGE:
					this.sendMessage(peerPubkey, action.messageType, action.payload);
					break;
				case ChannelActionType.CHANNEL_READY:
					this.emit('channel:ready', action.channelId);
					break;
				case ChannelActionType.CHANNEL_CLOSED:
					this.emit('channel:closed', action.channelId);
					break;
				case ChannelActionType.ERROR: {
					this.emit('error', channel.getChannelId(), action.message);
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
					this.emit('output:resolved', action.txid, action.outputIndex);
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
						this.emit('broadcast:tx', rebuilt);
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
			// The wallet covers the parent's fee deficit plus the child's own weight.
			const targetFeeSats = BigInt(
				Math.ceil(feeratePerVbyte * action.parentVbytes)
			);
			const { inputs, changeScript } = await fp.selectFeeBumpInputs(
				targetFeeSats,
				feeratePerKw
			);
			const { tx } = buildAnchorCpfpTx({
				commitmentTxid: action.commitmentTxid,
				anchorOutputIndex: action.anchorOutputIndex,
				anchorAmount: ANCHOR_OUTPUT_VALUE,
				anchorWitnessScript: action.anchorWitnessScript,
				localFundingPrivkey: this._channelFundingPrivkey(channelId),
				parentVbytes: action.parentVbytes,
				parentFeeSats: action.parentFeeSats,
				walletInputs: inputs,
				changeScript,
				feeratePerVbyte
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
			const anchorScript = buildAnchorOutput(
				state.localBasepoints.fundingPubkey
			).script;
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
				anchorWitnessScript: buildAnchorScript(
					state.localBasepoints.fundingPubkey
				),
				parentVbytes: commitmentTx.virtualSize(),
				parentFeeSats,
				commitmentTxid: commitmentTx.getId()
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

		const signer =
			channel.getSigner() ||
			new ChannelSigner(
				this.config.localFundingPrivkey,
				this.config.htlcBasepointSecret
			);
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
