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
	decodeClosingSignedMessage
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
import { signRemoteCommitment } from './commitment-builder';
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
	isAnchorChannel
} from './types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
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
import { decodeAnnouncementSignaturesMessage } from '../gossip/messages';
import { Feature } from '../features/flags';

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
	/** Chain hash for open_channel messages (defaults to Bitcoin mainnet) */
	chainHash?: Buffer;
	/** Node identity private key (for announcements) */
	nodePrivateKey?: Buffer;
	/** Per-channel key derivation callback. If provided, each new channel gets unique keys. */
	channelKeyDeriver?: (channelIndex: number) => IPerChannelKeys;
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
export class ChannelManager extends EventEmitter {
	private config: IChannelManagerConfig;
	private channels: Map<string, Channel> = new Map();
	private tempChannels: Map<string, Channel> = new Map();
	private channelPeers: Map<string, string> = new Map();
	private peerManager: PeerManager | null = null;
	private monitors: Map<string, ChainMonitor> = new Map();
	// Learned payment preimages, retained so monitors created later (on
	// force-close) can claim received HTLCs on-chain. Fed by recordPreimage().
	private _knownPreimages: Map<string, Buffer> = new Map();
	private zeroConfManager: ZeroConfManager = new ZeroConfManager();
	private _nextChannelIndex = 1;
	/** Wallet-owned destination for cooperative-close payouts, if configured. */
	private _walletDestinationScript: Buffer | null = null;
	/** Funding provider used to attach wallet inputs for anchor fee bumps. */
	private fundingProvider: IFundingProvider | null = null;

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
			this.config.preferAnchors
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
			this.config.preferAnchors
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
		if (fundingState.remoteCurrentPerCommitmentPoint) {
			const signer =
				channel.getSigner() ||
				new ChannelSigner(
					this.config.localFundingPrivkey,
					this.config.htlcBasepointSecret
				);
			const signed = signRemoteCommitment(
				fundingState,
				signer,
				fundingState.remoteCurrentPerCommitmentPoint
			);
			initialSignature = signed.signature;
		}

		const actions = channel.createFundingCreated(
			fundingTxid,
			fundingOutputIndex,
			initialSignature
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
	 * Add an HTLC to a channel.
	 */
	addHtlc(
		channelId: Buffer,
		amountMsat: bigint,
		paymentHash: Buffer,
		cltvExpiry: number,
		onionRoutingPacket: Buffer
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
			onionRoutingPacket
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
	 * Fail a received HTLC on a channel.
	 */
	failHtlc(channelId: Buffer, htlcId: bigint, reason: Buffer): ChannelResult {
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

		const actions = channel.failHtlc(htlcId, reason);
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
		const { signature, htlcSignatures } = signRemoteCommitment(
			state,
			signer,
			perCommitPoint,
			nextCommitNum
		);

		const actions = channel.signCommitment(signature, htlcSignatures);
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

		const actions = channel.initiateShutdown(scriptPubkey);
		this.processActions(peerPubkey, channel, actions);
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
		this._seedMonitorPreimages(monitor);
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
			this._seedMonitorPreimages(monitor);
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
	 * Restore a chain monitor from persisted state.
	 */
	restoreMonitor(channelId: string, monitor: ChainMonitor): void {
		this.monitors.set(channelId, monitor);
		this._seedMonitorPreimages(monitor);
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
	private _seedMonitorPreimages(monitor: ChainMonitor): void {
		for (const [hashHex, preimage] of this._knownPreimages) {
			monitor.addPreimage(Buffer.from(hashHex, 'hex'), preimage);
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
		const { signature } = signRemoteCommitment(
			channelState,
			signer,
			channelState.remoteCurrentPerCommitmentPoint!
		);

		const actions = channel.handleFundingCreated(msg, signature);

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
		const channel = this.findChannelByChannelId(msg.channelId);
		if (!channel) return;

		const actions = channel.handleCommitmentSigned(msg);
		const hasError = actions.some((a) => a.type === ChannelActionType.ERROR);
		this.processActions(peerPubkey, channel, actions);

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

		// Derive default P2WPKH shutdown script from local funding pubkey
		const defaultScript = this.getDefaultShutdownScript();
		const actions = channel.handleShutdown(msg, defaultScript);
		this.processActions(peerPubkey, channel, actions);

		// BOLT 2: opener must send first closing_signed after both shutdowns exchanged
		if (
			channel.getState() === ChannelState.NEGOTIATING_CLOSING &&
			channel.getRole() === ChannelRole.OPENER
		) {
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

		const actions = channel.handleClosingSigned(msg, (feeSatoshis: bigint) => {
			return this.signClosingTx(channel, feeSatoshis);
		});

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
				this.emit('broadcast:tx', closeTx);
			} else {
				this.emit(
					'error',
					msg.channelId,
					'Coop-close: peer closing signature failed to verify'
				);
			}
		}

		this.processActions(peerPubkey, channel, actions);
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
		const { tx, witnessScript, fundingSatoshis } =
			this.buildClosingTxAndScript(channel, feeSatoshis);
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
			// Opener re-proposes closing_signed to resume fee negotiation
			if (
				state === ChannelState.NEGOTIATING_CLOSING &&
				channel.getRole() === ChannelRole.OPENER
			) {
				const closingActions = channel.proposeClosingFee(
					(feeSatoshis: bigint) => this.signClosingTx(channel, feeSatoshis)
				);
				this.processActions(peerPubkey, channel, closingActions);
			}
		}
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
		const tempId = state.temporaryChannelId.toString('hex');
		this.tempChannels.set(tempId, channel);
		this.channelPeers.set(tempId, peerPubkey);

		const actions = channel.initiateOpenV2(params);
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
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddInput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAddOutput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxAddOutputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxAddOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveInput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxRemoveInputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveInput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxRemoveOutput(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxRemoveOutputMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxRemoveOutput(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxCompleteMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxCompleteMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxComplete();
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxSignaturesMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxSignaturesMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxSignatures(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxInitRbfMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxInitRbfMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
			this.findTempChannel(msg.channelId);
		if (!channel) return;

		const actions = channel.handleTxInitRbf(msg);
		this.processActions(peerPubkey, channel, actions);
	}

	private handleTxAbortMsg(peerPubkey: string, payload: Buffer): void {
		const msg = decodeTxAbortMessage(payload);
		const channel =
			this.findChannelByChannelId(msg.channelId) ||
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
			void this._handleFeeBumpAndBroadcast(channelId, {
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
			});
		} catch (err) {
			this.emit(
				'error',
				channelId,
				`anchor commitment CPFP setup failed: ${(err as Error).message}`
			);
		}
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
