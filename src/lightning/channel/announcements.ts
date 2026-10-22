/**
 * BOLT 7 announcement exchange for one channel: the announcement_signatures
 * we send at announcement depth and take from the peer, and the
 * channel_announcement and first channel_update built once both sides have
 * signed. Channel's methods of the same names delegate here and carry the
 * documentation.
 */

import { sha256 } from '../crypto/provider';
import { ecc } from '../../utils/ecc';
import { encodeShortChannelId } from '../gossip/types';
import {
	encodeAnnouncementSignaturesMessage,
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../gossip/messages';
import type { ISigner } from '../keys/signer';
import { MessageType } from '../message/types';
import type { ChannelAction } from './channel-actions';
import { ChannelActionType } from './channel-actions';
import type { IChannelState } from './channel-state';
import { sendMsg } from './channel-helpers';
import { ChannelState } from './types';

/** What the announcement exchange reads and writes on its channel. */
export interface IAnnouncementHost {
	state(): IChannelState;
	chainHash(): Buffer;
	signer(): ISigner | null;
	setScid(field: 'shortChannelId', scid: Buffer): void;
}

export class ChannelAnnouncements {
	private readonly _host: IAnnouncementHost;

	constructor(host: IAnnouncementHost) {
		this._host = host;
	}

	// Read through the host at each use: the manager sets the chain hash and
	// the signer after the channel is built.
	private get _state(): IChannelState {
		return this._host.state();
	}

	private get announcementChainHash(): Buffer {
		return this._host.chainHash();
	}

	private get _signer(): ISigner | null {
		return this._host.signer();
	}

	private _setScid(field: 'shortChannelId', scid: Buffer): void {
		this._host.setScid(field, scid);
	}

	handleAnnouncementDepthReached(
		blockHeight: number,
		txIndex: number,
		localNodeId: Buffer,
		remoteNodeId: Buffer,
		signAnnouncement: (data: Buffer) => { nodeSig: Buffer; bitcoinSig: Buffer }
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			// Not announceable right now (force-closed/closing, or transiently
			// AWAITING_REESTABLISH after a restart). This is a no-op, NOT an error:
			// the funding simply reached announcement depth while the channel isn't
			// in a state to announce. Returning an ERROR here spammed the logs every
			// time a closed channel's funding crossed 6 confirmations.
			return [];
		}

		// Compute real SCID for ALL channels (needed for routing hints on private channels)
		const scid = encodeShortChannelId({
			block: blockHeight,
			txIndex,
			outputIndex: this._state.fundingOutputIndex
		});
		this._setScid('shortChannelId', scid);
		this._state.fundingConfirmationHeight = blockHeight;
		this._state.fundingTxIndex = txIndex;

		if (!this._state.announceChannel) {
			return []; // Private channel — no announcement, but SCID is set for routing hints
		}
		if (this._state.announcementSigsSent) {
			return []; // Already sent
		}

		// Build the channel_announcement data to sign
		const announcementData = this.buildAnnouncementData(
			localNodeId,
			remoteNodeId
		);
		const sigs = signAnnouncement(announcementData);

		// Encode announcement_signatures message
		const payload = encodeAnnouncementSignaturesMessage({
			channelId: this._state.channelId!,
			shortChannelId: scid,
			nodeSignature: sigs.nodeSig,
			bitcoinSignature: sigs.bitcoinSig
		});

		this._state.announcementSigsSent = true;
		// Store local sigs for later use when remote sigs arrive
		this._state.localAnnouncementNodeSig = sigs.nodeSig;
		this._state.localAnnouncementBitcoinSig = sigs.bitcoinSig;

		const actions: ChannelAction[] = [
			sendMsg(MessageType.ANNOUNCEMENT_SIGNATURES, payload),
			// Persist the freshly stored local signatures + SCID immediately.
			{ type: ChannelActionType.PERSIST_STATE }
		];

		// If we already have remote sigs, construct the full announcement
		if (this._state.announcementSigsReceived) {
			const ready = this.buildFullAnnouncement(
				localNodeId,
				remoteNodeId,
				sigs.nodeSig,
				sigs.bitcoinSig
			);
			if (ready) actions.push(ready);
		}

		return actions;
	}

	handleAnnouncementSignatures(
		msg: {
			channelId: Buffer;
			shortChannelId: Buffer;
			nodeSignature: Buffer;
			bitcoinSignature: Buffer;
		},
		localNodeId: Buffer,
		remoteNodeId: Buffer,
		localNodeSig?: Buffer,
		localBitcoinSig?: Buffer
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			// Silently ignore during closing — peer may retransmit after reestablish
			return [];
		}

		// A different SCID than ours means the peer is announcing a newer
		// funding generation (post-splice): the funding outpoint moved, so any
		// signatures exchanged over the previous SCID are invalid for this
		// announcement. Adopt the new SCID and discard our stale local
		// signatures — the announcement:needs-signing path re-signs over the
		// new SCID (after verifying it points at our funding tx). Combining the
		// peer's new-SCID signatures with our old SCID/signatures produces an
		// announcement the network rejects ("Bad node_signature_1").
		if (
			this._state.shortChannelId &&
			!this._state.shortChannelId.equals(msg.shortChannelId)
		) {
			this._setScid('shortChannelId', msg.shortChannelId);
			this._state.announcementSigsSent = false;
			this._state.localAnnouncementNodeSig = null;
			this._state.localAnnouncementBitcoinSig = null;
		}

		this._state.remoteAnnouncementNodeSig = msg.nodeSignature;
		this._state.remoteAnnouncementBitcoinSig = msg.bitcoinSignature;
		this._state.announcementSigsReceived = true;

		// If we don't have an SCID yet, use theirs
		if (!this._state.shortChannelId) {
			this._setScid('shortChannelId', msg.shortChannelId);
		}

		// Persist exchanged signatures + adopted SCID so a restart doesn't
		// resurrect a stale pre-splice announcement state.
		const actions: ChannelAction[] = [
			{ type: ChannelActionType.PERSIST_STATE }
		];

		// If both sides have exchanged sigs, build the full announcement
		if (this._state.announcementSigsSent && localNodeSig && localBitcoinSig) {
			// Self-heal a stored bitcoin signature made with the wrong key (older
			// versions signed with the node-level base funding key while the
			// announcement advertises the per-channel key — peers reject it with
			// "Bad bitcoin_signature"). Verify against the advertised key and
			// re-sign with the channel signer when invalid.
			localBitcoinSig = this._repairAnnouncementBitcoinSig(
				localNodeId,
				remoteNodeId,
				localBitcoinSig
			);
			const ready = this.buildFullAnnouncement(
				localNodeId,
				remoteNodeId,
				localNodeSig,
				localBitcoinSig
			);
			if (ready) actions.push(ready);
		}

		return actions;
	}

	/**
	 * Verify our stored channel_announcement bitcoin signature against the
	 * funding pubkey the announcement advertises; re-sign with the channel
	 * signer (and persist on state) when it does not verify.
	 */
	private _repairAnnouncementBitcoinSig(
		localNodeId: Buffer,
		remoteNodeId: Buffer,
		storedSig: Buffer
	): Buffer {
		const data = this.buildAnnouncementData(localNodeId, remoteNodeId);
		const hash = sha256(sha256(data));
		try {
			if (
				ecc.verify(hash, this._state.localBasepoints.fundingPubkey, storedSig)
			) {
				return storedSig;
			}
		} catch {
			// malformed signature — fall through to re-sign
		}
		if (!this._signer) return storedSig;
		const fresh = this._signer.signFundingDigest(hash);
		try {
			// Adopt only if the signer actually holds the advertised key —
			// otherwise keep the stored sig rather than replace one bad sig
			// with another.
			if (!ecc.verify(hash, this._state.localBasepoints.fundingPubkey, fresh)) {
				return storedSig;
			}
		} catch {
			return storedSig;
		}
		this._state.localAnnouncementBitcoinSig = fresh;
		return fresh;
	}

	private buildAnnouncementData(
		localNodeId: Buffer,
		remoteNodeId: Buffer
	): Buffer {
		const localBp = this._state.localBasepoints;
		const remoteBp = this._state.remoteBasepoints!;

		const isNode1 = Buffer.compare(localNodeId, remoteNodeId) < 0;
		const nodeId1 = isNode1 ? localNodeId : remoteNodeId;
		const nodeId2 = isNode1 ? remoteNodeId : localNodeId;
		const bitcoinKey1 = isNode1
			? localBp.fundingPubkey
			: remoteBp.fundingPubkey;
		const bitcoinKey2 = isNode1
			? remoteBp.fundingPubkey
			: localBp.fundingPubkey;

		// channel_announcement signed data (after the 4 signatures):
		// [2: flen] [flen: features] [32: chain_hash] [8: scid]
		// [33: node_id_1] [33: node_id_2] [33: bitcoin_key_1] [33: bitcoin_key_2]
		const flen = Buffer.alloc(2);
		const parts = [
			flen,
			this.announcementChainHash,
			this._state.shortChannelId!,
			nodeId1,
			nodeId2,
			bitcoinKey1,
			bitcoinKey2
		];
		return Buffer.concat(parts);
	}

	rebuildAnnouncement(
		localNodeId: Buffer,
		remoteNodeId: Buffer
	): ChannelAction | null {
		const nodeSig = this._state.localAnnouncementNodeSig;
		const bitcoinSig = this._state.localAnnouncementBitcoinSig;
		if (
			!this._state.announceChannel ||
			!this._state.shortChannelId ||
			!nodeSig ||
			!bitcoinSig
		) {
			return null;
		}
		return this.buildFullAnnouncement(
			localNodeId,
			remoteNodeId,
			nodeSig,
			bitcoinSig
		);
	}

	private buildFullAnnouncement(
		localNodeId: Buffer,
		remoteNodeId: Buffer,
		localNodeSig: Buffer,
		localBitcoinSig: Buffer
	): ChannelAction | null {
		if (
			!this._state.remoteAnnouncementNodeSig ||
			!this._state.remoteAnnouncementBitcoinSig
		) {
			return null;
		}

		const isNode1 = Buffer.compare(localNodeId, remoteNodeId) < 0;

		const localBp = this._state.localBasepoints;
		const remoteBp = this._state.remoteBasepoints!;

		// Construct the full channel_announcement message
		const announcement = encodeChannelAnnouncementMessage({
			nodeSignature1: isNode1
				? localNodeSig
				: this._state.remoteAnnouncementNodeSig,
			nodeSignature2: isNode1
				? this._state.remoteAnnouncementNodeSig
				: localNodeSig,
			bitcoinSignature1: isNode1
				? localBitcoinSig
				: this._state.remoteAnnouncementBitcoinSig,
			bitcoinSignature2: isNode1
				? this._state.remoteAnnouncementBitcoinSig
				: localBitcoinSig,
			features: Buffer.alloc(0),
			chainHash: this.announcementChainHash,
			shortChannelId: this._state.shortChannelId!,
			nodeId1: isNode1 ? localNodeId : remoteNodeId,
			nodeId2: isNode1 ? remoteNodeId : localNodeId,
			bitcoinKey1: isNode1 ? localBp.fundingPubkey : remoteBp.fundingPubkey,
			bitcoinKey2: isNode1 ? remoteBp.fundingPubkey : localBp.fundingPubkey
		});

		// Build initial channel_update (direction = our direction bit)
		const directionBit = isNode1 ? 0 : 1;
		// BOLT 7: htlc_maximum_msat MUST be <= channel capacity
		const capacityMsat = this._state.fundingSatoshis * 1000n;
		const htlcMaxMsat =
			this._state.localConfig.maxHtlcValueInFlightMsat > capacityMsat
				? capacityMsat
				: this._state.localConfig.maxHtlcValueInFlightMsat;

		const channelUpdate = encodeChannelUpdateMessage({
			signature: Buffer.alloc(64), // placeholder — caller should sign
			chainHash: this.announcementChainHash,
			shortChannelId: this._state.shortChannelId!,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 0x01,
			channelFlags: directionBit,
			cltvExpiryDelta: this._state.localConfig.toSelfDelay,
			htlcMinimumMsat: this._state.localConfig.htlcMinimumMsat,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: htlcMaxMsat
		});

		return {
			type: ChannelActionType.ANNOUNCEMENT_READY,
			channelAnnouncement: announcement,
			channelUpdate,
			channelId: this._state.channelId!
		};
	}
}
