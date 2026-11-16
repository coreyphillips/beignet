/**
 * Serialization helpers for Lightning state persistence.
 *
 * Converts complex types (Buffer, bigint, Maps, ShaChainStore, etc.)
 * to/from JSON-safe representations for SQLite storage.
 */

import type {
	IChannelState,
	ISpliceInFlight,
	IV2InFlight,
	ChannelCloseReason
} from '../channel/channel-state';
import type {
	FforConcurrentVersion,
	FforAbortReason,
	FforRole,
	FforSlotState,
	FforState,
	IFforEpochRecord
} from '../ffor/types';
import { isFforConcurrentVersion } from '../ffor/types';
import { fforTranscriptConcurrentVersion } from '../ffor/messages';
import { validateFforSyncState } from '../ffor/sync-state';
import type { IShaChainEntry } from '../keys/shachain';
import { ShaChainStore } from '../keys/shachain';
import type { IChannelBasepoints } from '../keys/derivation';
import type {
	ChannelState,
	ChannelRole,
	IChannelConfig,
	IHtlcEntry,
	IHtlcSnapshotEntry,
	HtlcDirection
} from '../channel/types';
import { DEFAULT_CHANNEL_CONFIG, isOverlayChannel } from '../channel/types';
import type {
	IPaymentInfo,
	PaymentStatus,
	PaymentDirection
} from '../node/payment-types';
import type { IChainMonitorState } from '../chain/chain-monitor';
import type { IGraphChannel, IGraphNode } from '../gossip/types';
import type { IInvoiceInfo } from './types';
import type { ICompactHtlcHistory } from './htlc-history';
import {
	encodeHtlcHistory,
	decodeHtlcHistory,
	usesCompactHtlcHistory
} from './htlc-history';
import { unsavedRevokedHtlcSnapshots } from '../channel/htlc-snapshots';
import { addWithoutOnion, restoreAddOnion } from './add-onion';
import {
	bufToHex,
	hexToBuf,
	bigintToStr,
	strToBigint
} from './serialization-primitives';
import { serializeHtlcEntry, deserializeHtlcEntry } from './htlc-serialization';
import type { ISerializedHtlcEntry } from './htlc-serialization';
import {
	serializeAuxiliaryState,
	deserializeAuxiliaryState,
	serializeCustomRecords,
	deserializeCustomRecords
} from './auxiliary-serialization';
import type {
	ISerializedAuxiliaryState,
	SerializedCustomRecords
} from './auxiliary-serialization';

// ─── Primitive helpers ───

export {
	bufToHex,
	hexToBuf,
	bigintToStr,
	strToBigint
} from './serialization-primitives';

// ─── IChannelConfig ───

export interface ISerializedChannelConfig {
	dustLimitSatoshis: string;
	maxHtlcValueInFlightMsat: string;
	channelReserveSatoshis: string;
	htlcMinimumMsat: string;
	toSelfDelay: number;
	maxAcceptedHtlcs: number;
	feeratePerKw: number;
}

export function serializeChannelConfig(
	c: IChannelConfig
): ISerializedChannelConfig {
	return {
		dustLimitSatoshis: bigintToStr(c.dustLimitSatoshis),
		maxHtlcValueInFlightMsat: bigintToStr(c.maxHtlcValueInFlightMsat),
		channelReserveSatoshis: bigintToStr(c.channelReserveSatoshis),
		htlcMinimumMsat: bigintToStr(c.htlcMinimumMsat),
		toSelfDelay: c.toSelfDelay,
		maxAcceptedHtlcs: c.maxAcceptedHtlcs,
		feeratePerKw: c.feeratePerKw
	};
}

export function deserializeChannelConfig(
	s: ISerializedChannelConfig
): IChannelConfig {
	return {
		dustLimitSatoshis: strToBigint(s.dustLimitSatoshis),
		maxHtlcValueInFlightMsat: strToBigint(s.maxHtlcValueInFlightMsat),
		channelReserveSatoshis: strToBigint(s.channelReserveSatoshis),
		htlcMinimumMsat: strToBigint(s.htlcMinimumMsat),
		toSelfDelay: s.toSelfDelay,
		maxAcceptedHtlcs: s.maxAcceptedHtlcs,
		feeratePerKw: s.feeratePerKw
	};
}

// ─── IChannelBasepoints ───

export interface ISerializedBasepoints {
	fundingPubkey: string;
	revocationBasepoint: string;
	paymentBasepoint: string;
	delayedPaymentBasepoint: string;
	htlcBasepoint: string;
	firstPerCommitmentPoint: string;
}

export function serializeBasepoints(
	bp: IChannelBasepoints
): ISerializedBasepoints {
	return {
		fundingPubkey: bp.fundingPubkey.toString('hex'),
		revocationBasepoint: bp.revocationBasepoint.toString('hex'),
		paymentBasepoint: bp.paymentBasepoint.toString('hex'),
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint.toString('hex'),
		htlcBasepoint: bp.htlcBasepoint.toString('hex'),
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint.toString('hex')
	};
}

export function deserializeBasepoints(
	s: ISerializedBasepoints
): IChannelBasepoints {
	return {
		fundingPubkey: Buffer.from(s.fundingPubkey, 'hex'),
		revocationBasepoint: Buffer.from(s.revocationBasepoint, 'hex'),
		paymentBasepoint: Buffer.from(s.paymentBasepoint, 'hex'),
		delayedPaymentBasepoint: Buffer.from(s.delayedPaymentBasepoint, 'hex'),
		htlcBasepoint: Buffer.from(s.htlcBasepoint, 'hex'),
		firstPerCommitmentPoint: Buffer.from(s.firstPerCommitmentPoint, 'hex')
	};
}

// ─── IHtlcEntry ───

export { serializeHtlcEntry, deserializeHtlcEntry } from './htlc-serialization';
export type { ISerializedHtlcEntry } from './htlc-serialization';

export interface ISerializedHtlcSnapshot {
	commitmentNumber: string;
	htlcs: Array<{
		paymentHash: string;
		amountMsat: string;
		cltvExpiry: number;
		direction: string;
	}>;
}

export function serializeHtlcSnapshotEntries(
	entries: IHtlcSnapshotEntry[]
): ISerializedHtlcSnapshot['htlcs'] {
	return entries.map((e) => ({
		paymentHash: e.paymentHash.toString('hex'),
		amountMsat: bigintToStr(e.amountMsat),
		cltvExpiry: e.cltvExpiry,
		direction: e.direction
	}));
}

export function deserializeHtlcSnapshotEntries(
	htlcs: ISerializedHtlcSnapshot['htlcs']
): IHtlcSnapshotEntry[] {
	return htlcs.map((e) => ({
		paymentHash: Buffer.from(e.paymentHash, 'hex'),
		amountMsat: strToBigint(e.amountMsat),
		cltvExpiry: e.cltvExpiry,
		direction: e.direction as HtlcDirection
	}));
}

// ─── ShaChainStore ───

export interface ISerializedShaChainEntry {
	index: string;
	secret: string;
}

export function serializeShaChainEntries(store: ShaChainStore): {
	entries: ISerializedShaChainEntry[];
	knownCount: string;
} {
	return {
		entries: store.getEntries().map((e) => ({
			index: bigintToStr(e.index),
			secret: e.secret.toString('hex')
		})),
		knownCount: bigintToStr(store.getKnownCount())
	};
}

export function deserializeShaChainStore(data: {
	entries: ISerializedShaChainEntry[];
	knownCount: string;
}): ShaChainStore {
	const entries: IShaChainEntry[] = data.entries.map((e) => ({
		index: strToBigint(e.index),
		secret: Buffer.from(e.secret, 'hex')
	}));
	return ShaChainStore.restore(entries, strToBigint(data.knownCount));
}

// ─── IChannelState ───

export interface ISerializedChannelState {
	channelId: string | null;
	temporaryChannelId: string;
	role: string;
	state: string;
	fundingSatoshis: string;
	pushMsat: string;
	fundingTxid: string | null;
	pendingFundingTxHex?: string;
	fundingTxHex?: string;
	fundingMissingSinceHeight?: number;
	/**
	 * Issue #593: the funding is unaccounted for on chain and the channel is
	 * quarantined against NEW HTLCs. MUST persist - a restart must not lift a
	 * quarantine the chain has not lifted.
	 */
	fundingUnaccounted?: boolean;
	/** A splice has been adopted at least once (see IChannelState). */
	hasBeenSpliced?: boolean;
	/**
	 * Funding txids retired by adopted splices, oldest first, internal byte
	 * order hex (issue #1060). Absent on rows written before the field.
	 */
	previousFundingTxids?: string[];
	/**
	 * Funding txids this channel has locked, oldest first, internal byte order
	 * hex (issue #1899). Absent on rows written before the field.
	 */
	lockedFundingTxids?: string[];
	fundingOutputIndex: number;
	minimumDepth: number;
	localConfig: ISerializedChannelConfig;
	localBasepoints: ISerializedBasepoints;
	localPerCommitmentSeed: string;
	remoteConfig: ISerializedChannelConfig;
	remoteBasepoints: ISerializedBasepoints | null;
	localCommitmentNumber: string;
	remoteCommitmentNumber: string;
	/**
	 * Count of revoke_and_ack messages received from the peer (next remote
	 * revocation index). Optional for backward compatibility; absent means
	 * "in sync with remoteCommitmentNumber" (see Channel accessors).
	 */
	remoteRevocationNumber?: string;
	needsCommitment?: boolean;
	/**
	 * A staged (uncommitted) update_fee rate. Persisted so a restart mid
	 * fee-round restores the exact rate the in-flight commitment was built
	 * with. Optional for backward compatibility.
	 */
	pendingFeeratePerKw?: number;
	/**
	 * Two-phase update_fee phases for the staged rate (see IChannelState).
	 * Optional for backward compatibility.
	 */
	pendingFeerateSignable?: boolean;
	pendingFeerateCommitted?: boolean;
	awaitingLocalFeeCommitment?: boolean;
	/**
	 * The feerate baked into the current signed local commitment (the rate
	 * remoteCommitmentSignature covers) — force-close rebuilds at this rate.
	 * Optional for backward compatibility.
	 */
	lastSignedCommitFeeratePerKw?: number;
	/**
	 * Two-phase update_blockheight (bLIP-0051 leases): staged height, its
	 * phases, the height the current signed local commitment was built at,
	 * and every distinct committed height (old-commitment classification).
	 * All optional for backward compatibility.
	 */
	pendingLeaseBlockheight?: number;
	pendingLeaseBlockheightSignable?: boolean;
	pendingLeaseBlockheightCommitted?: boolean;
	lastSignedCommitLeaseBlockheight?: number;
	leaseHeightHistory?: number[];
	localBalanceMsat: string;
	remoteBalanceMsat: string;
	shaChainData: { entries: ISerializedShaChainEntry[]; knownCount: string };
	remoteCurrentPerCommitmentPoint: string | null;
	remoteNextPerCommitmentPoint: string | null;
	localHtlcCounter: string;
	htlcs: ISerializedHtlcEntry[];
	/**
	 * Received removals the signed local commitment still carries (see
	 * IChannelState.signedLocalRemovals). Absent when there are none, so a row
	 * outside that window is byte for byte what it was.
	 */
	signedLocalRemovals?: ISerializedHtlcEntry[];
	/** Per-remote-commitment HTLC snapshots for penalty completeness (H2). */
	revokedHtlcSnapshots?: ISerializedHtlcSnapshot[];
	compactHtlcHistory?: ICompactHtlcHistory;
	/**
	 * Unrevoked remote commitment txs kept for watchtower backups. A point
	 * repeats once per funding output it was signed over.
	 */
	watchtowerRemoteCommitmentTxs?: Array<{ point: string; tx: string }>;
	/** Revoked remote commitment txs whose watchtower hand-off failed. */
	watchtowerBackupsOwed?: Array<{ secret: string; tx: string }>;
	remoteCommitmentSignature: string | null;
	remoteHtlcSignatures: string[];
	/**
	 * option_taproot: the peer's 66-byte signing nonce for the current local
	 * commitment, persisted so a restored taproot channel can still aggregate the
	 * key-spend witness at force-close. Optional for backward compatibility with
	 * pre-taproot serialized states.
	 */
	remoteSigningNonce?: string | null;
	channelType: string | null;
	localChannelReady: boolean;
	remoteChannelReady: boolean;
	condemned?: boolean;
	localShutdownScript: string | null;
	remoteShutdownScript: string | null;
	lastSentCommitmentSigned: string | null;
	lastSentPartialSignatureWithNonce: string | null;
	lastSentHtlcSignatures: string[];
	lastSentRevokeSecret: string | null;
	lastSentRevokeNextPoint: string | null;
	lastSentWasRevoke?: boolean | null;
	/**
	 * `onionFromHtlc` marks an update_add_htlc journaled without its onion,
	 * which the offered HTLC entry it added carries (recovery frame version
	 * 4). Local storage always writes the whole message.
	 */
	pendingLocalUpdates?: Array<{
		type: number;
		payloadHex: string;
		onionFromHtlc?: true;
	}>;
	pendingLocalUpdatesSignedCount?: number;
	preReestablishState: string | null;
	lastProposedClosingFeeSat: string | null;
	closingFeeMin: string | null;
	closingFeeMax: string | null;
	theirLastClosingFeeSat: string | null;
	/**
	 * option_simple_close. Optional for backward compatibility with pre-simple-
	 * close serialized states (all-absent deserializes to legacy behavior).
	 * awaitingClosingSig is intentionally NOT persisted — negotiation restarts
	 * on reconnect per spec.
	 */
	simpleClose?: boolean | null;
	lastCloseFeeSat?: string | null;
	lastCloseLocktime?: number | null;
	lastCloseCloserScript?: string | null;
	lastCloseCloseeScript?: string | null;
	lastCloseSentVariants?: number[] | null;
	shortChannelId: string | null;
	fundingConfirmationHeight: number;
	fundingBroadcastHeight?: number;
	fundingTxIndex: number;
	announcementSigsSent: boolean;
	announcementSigsReceived: boolean;
	remoteAnnouncementNodeSig: string | null;
	remoteAnnouncementBitcoinSig: string | null;
	localAnnouncementNodeSig: string | null;
	localAnnouncementBitcoinSig: string | null;
	announceChannel: boolean;
	scidAlias: string | null;
	remoteScidAlias: string | null;
	zeroConfEnabled?: boolean;
	trustedPeer?: boolean;
	quiescenceState?: string;
	quiescenceInitiator?: boolean;
	spliceFundingTxid?: string | null;
	spliceFundingOutputIndex?: number;
	preSpliceState?: string | null;
	spliceInFlight?: ISerializedSpliceInFlight | null;
	/** Issue #764: splice (internal hex) the broadcast force close spends. */
	closeSpendsSpliceTxid?: string | null;
	/** Issue #1523: funding (internal hex) the last broadcast force close spends. */
	closeSpendsFundingTxid?: string;
	/** Issue #756: fully signed splice txs not yet seen confirmed (txid internal hex). */
	unconfirmedSpliceTxs?: Array<{ txid: string; txHex: string }>;
	/** Issue #760: splices reverted on a confirmed input conflict (display hex). */
	revertedSplices?: Array<{
		spliceTxid: string;
		conflictTxid: string;
		revertedAt: number;
		commitmentNumber: string;
		spliceTxHex: string;
		newFundingOutputIndex: number;
		remoteFundingPubkey: string;
		remoteCommitmentSig: string | null;
		remoteHtlcSignatures?: string[];
		remoteCommitmentSigFeeratePerKw?: number;
	}>;
	spliceAbortOwed?: boolean;
	remoteForwardingPolicy?: {
		feeBaseMsat: number;
		feeProportionalMillionths: number;
		cltvExpiryDelta: number;
		htlcMinimumMsat: string;
		htlcMaximumMsat: string | null;
		timestamp: number;
	} | null;
	fundingVersion?: number;
	/**
	 * Which generation of the code wrote localConfig.channelReserveSatoshis.
	 * Absent on every row written before it existed, which is exactly what
	 * authorizes the load-time repair to re-derive those (issue #381).
	 */
	channelReserveVersion?: number;
	localReserveWaived?: boolean;
	remoteReserveWaived?: boolean;
	commitmentFeeratePerkw?: number;
	fundingLocktime?: number;
	v2InFlight?: ISerializedV2InFlight | null;
	// Broadcastable attempts superseded by an accepted RBF, newest last;
	// absent on rows written before the spec-window RBF support (issue #360).
	v2PreviousAttempts?: ISerializedV2InFlight[];
	// Liquidity ads (bLIP-0051): if we are the lessor, our to_local (and its
	// exact on-chain script) is CLTV-locked until leaseExpiry. These MUST persist —
	// otherwise a restart rebuilds the commitment without the lock, the peer's cached
	// signature no longer validates, and our whole balance becomes unbroadcastable.
	isLessor?: boolean;
	leaseExpiry?: number;
	leaseCommitBlockheight?: number;
	// Cooperative close: fully-signed mutual-close tx (hex). Persisted so a restart
	// in the pre-confirmation window can rebroadcast it and re-arm the funding watch.
	lastCooperativeCloseTxHex?: string;
	externalClose?: {
		scriptHex: string;
		timestamp: number;
		transactions?: Array<{ txHex: string; localFeeSats: number }>;
	};
	// Data loss protection: MUST persist - a restart after detecting we fell
	// behind would otherwise forget the flag and let a force-close broadcast
	// our stale (revoked) commitment.
	dataLossDetected?: boolean;
	// Issue #413: the funding reached depth in a state whose ready flow could
	// not consume it (zero-conf fast-track, or already failed). MUST persist -
	// it is the durable proof the outpoint exists that lets a restart's
	// failure-resolution paths broadcast the owed close.
	fundingConfirmedLate?: boolean;
	// Recovery 5.6 StateUncertain: MUST persist for the same reason - a
	// restart of a possibly-stale restore must not forget that broadcasting
	// is forbidden until reestablish proves the state current.
	stateUncertain?: boolean;
	// Issue #479: funding outpoints a splice superseded whose spend must still
	// be watched, with the splice tx expected to spend each. MUST persist -
	// spliceInFlight is cleared at splice_locked, so it cannot rebuild this
	// watch after a restart, and the old outpoint would go unwatched.
	preSpliceSpendWatches?: Array<{
		txid: string;
		outputIndex: number;
		script: string;
		spliceTxid: string;
	}>;
	// Issue #469: this row came from a Recovery Capsule, whose recency nothing
	// can prove. MUST persist - a restart must not forget that an AUTOMATIC
	// commitment broadcast is forbidden.
	restoreRecencyUnproven?: boolean;
	// Issue #907: the peer's channel_reestablish claimed this row is behind
	// and showed no proof. Same hold as the flag above. MUST persist - a
	// restart must not forget that an AUTOMATIC commitment broadcast is
	// forbidden.
	reestablishRecencyUnproven?: boolean;
	// Issue #919: this node's own shachain store could not produce the
	// per-commitment secret its channel_reestablish owes the peer. Same hold
	// as the two flags above, from a local fault. MUST persist - a restart
	// must not forget that an AUTOMATIC commitment broadcast is forbidden,
	// and the store cannot recover the secret, so the flag never clears.
	reestablishSecretMissing?: boolean;
	// Issues #905 and #915: the peer has shown it holds the revocation for
	// this row's current commitment, with or without a capsule restore.
	// MUST persist - a restart must not reopen
	// the operator's force close on a commitment the peer can punish.
	restoreRevokedRisk?: boolean;
	// Issue #469: the operator acknowledged the stale-close risk when
	// initiating a mutual close of the row above. MUST persist - a restart
	// inside the negotiation must not turn the authorized close into a
	// refusal.
	staleCloseRiskAccepted?: boolean;
	// Recovery 5.6 liveness: the persisted peer-close disposition; the wire
	// error is regenerated from this on every reconnect. 'restore-unproven',
	// 'reestablish-unproven' and 'reestablish-secret-missing' are DERIVED from
	// the flags above rather than stamped, so they are never written here; the
	// union carries them so the two types stay one shape.
	recoveryCloseReason?:
		| 'local-data-loss'
		| 'state-uncertain'
		| 'restore-unproven'
		| 'reestablish-unproven'
		| 'reestablish-secret-missing';
	// Why WE closed the channel ('user' or an automatic close code).
	closeReason?: ChannelCloseReason;
	dlpRemotePerCommitmentPoint?: string | null;
	/** FFOR Variant D epoch record (see IChannelState.ffor). */
	ffor?: ISerializedFforEpoch | null;
	fforUsedEpochIds?: string[];
	/**
	 * Asset channels only (see IChannelState). Each key is written only when
	 * the channel has the value, so the row of every other channel is the
	 * bytes it always was.
	 */
	fundingTaprootMerkleRoot?: string;
	auxiliaryState?: ISerializedAuxiliaryState;
	lastSentAuxiliaryRecords?: SerializedCustomRecords;
}

export interface ISerializedSpliceInFlight {
	spliceTxid: string;
	newFundingOutputIndex: number;
	newFundingSatoshis: string;
	spliceTxHex: string;
	fullySigned: boolean;
	isInitiator: boolean;
	localRelativeSatoshis: string;
	remoteRelativeSatoshis: string;
	remoteFundingPubkey: string;
	ourSharedInputSig: string;
	remoteSharedInputSig?: string;
	ourWalletWitnesses: string[][];
	ourWalletInputIndices: number[];
	// Issue #592: tx-input indices of externally owned splice inputs whose
	// witnesses arrive out of band; absent on records without external inputs.
	externalInputIndices?: number[];
	inputPrevouts?: Array<{ script: string; valueSats: string }>;
	remoteCommitmentSig: string | null;
	remoteCommitmentSigFeeratePerKw?: number;
	remoteCommitmentSigLeaseBlockheight?: number;
	remoteHtlcSignatures?: string[];
	sentTxSignatures: boolean;
	receivedTxSignatures: boolean;
	localSpliceLocked: boolean;
	remoteSpliceLocked: boolean;
	confirmed: boolean;
	/** Issue #764: height the splice was first seen in, below its lock depth. */
	confirmedHeight?: number;
	/** Issue #760: per-splice lock depth; absent on older rows. */
	lockAtDepth?: number;
	/** Issue #760: the confirmed competing spend of one of its inputs. */
	conflict?: {
		txid: string;
		height: number;
		inputIndex: number;
		revertRequestedAt?: number;
	};
}

export function serializeSpliceInFlight(
	f: ISpliceInFlight
): ISerializedSpliceInFlight {
	return {
		spliceTxid: f.spliceTxid.toString('hex'),
		newFundingOutputIndex: f.newFundingOutputIndex,
		newFundingSatoshis: bigintToStr(f.newFundingSatoshis),
		spliceTxHex: f.spliceTxHex,
		fullySigned: f.fullySigned,
		isInitiator: f.isInitiator,
		localRelativeSatoshis: bigintToStr(f.localRelativeSatoshis),
		remoteRelativeSatoshis: bigintToStr(f.remoteRelativeSatoshis),
		remoteFundingPubkey: f.remoteFundingPubkey.toString('hex'),
		ourSharedInputSig: f.ourSharedInputSig.toString('hex'),
		remoteSharedInputSig: f.remoteSharedInputSig?.toString('hex'),
		ourWalletWitnesses: f.ourWalletWitnesses.map((w) =>
			w.map((b) => b.toString('hex'))
		),
		ourWalletInputIndices: [...f.ourWalletInputIndices],
		externalInputIndices: f.externalInputIndices
			? [...f.externalInputIndices]
			: undefined,
		inputPrevouts: f.inputPrevouts.map((p) => ({
			script: p.script.toString('hex'),
			valueSats: bigintToStr(p.valueSats)
		})),
		remoteCommitmentSig: bufToHex(f.remoteCommitmentSig),
		remoteCommitmentSigFeeratePerKw: f.remoteCommitmentSigFeeratePerKw,
		remoteCommitmentSigLeaseBlockheight: f.remoteCommitmentSigLeaseBlockheight,
		remoteHtlcSignatures: f.remoteHtlcSignatures?.map((b) => b.toString('hex')),
		sentTxSignatures: f.sentTxSignatures,
		receivedTxSignatures: f.receivedTxSignatures,
		localSpliceLocked: f.localSpliceLocked,
		remoteSpliceLocked: f.remoteSpliceLocked,
		confirmed: f.confirmed,
		confirmedHeight: f.confirmedHeight,
		lockAtDepth: f.lockAtDepth,
		conflict: f.conflict ? { ...f.conflict } : undefined
	};
}

export function deserializeSpliceInFlight(
	s: ISerializedSpliceInFlight
): ISpliceInFlight {
	return {
		spliceTxid: Buffer.from(s.spliceTxid, 'hex'),
		newFundingOutputIndex: s.newFundingOutputIndex,
		newFundingSatoshis: strToBigint(s.newFundingSatoshis),
		spliceTxHex: s.spliceTxHex,
		fullySigned: s.fullySigned,
		isInitiator: s.isInitiator,
		localRelativeSatoshis: strToBigint(s.localRelativeSatoshis),
		remoteRelativeSatoshis: strToBigint(s.remoteRelativeSatoshis),
		remoteFundingPubkey: Buffer.from(s.remoteFundingPubkey, 'hex'),
		ourSharedInputSig: Buffer.from(s.ourSharedInputSig, 'hex'),
		remoteSharedInputSig:
			s.remoteSharedInputSig !== undefined
				? Buffer.from(s.remoteSharedInputSig, 'hex')
				: undefined,
		ourWalletWitnesses: s.ourWalletWitnesses.map((w) =>
			w.map((h) => Buffer.from(h, 'hex'))
		),
		ourWalletInputIndices: [...s.ourWalletInputIndices],
		externalInputIndices: s.externalInputIndices
			? [...s.externalInputIndices]
			: undefined,
		inputPrevouts: (s.inputPrevouts ?? []).map((p) => ({
			script: Buffer.from(p.script, 'hex'),
			valueSats: strToBigint(p.valueSats)
		})),
		remoteCommitmentSig: hexToBuf(s.remoteCommitmentSig),
		remoteCommitmentSigFeeratePerKw: s.remoteCommitmentSigFeeratePerKw,
		remoteCommitmentSigLeaseBlockheight: s.remoteCommitmentSigLeaseBlockheight,
		remoteHtlcSignatures: s.remoteHtlcSignatures?.map((h) =>
			Buffer.from(h, 'hex')
		),
		sentTxSignatures: s.sentTxSignatures,
		receivedTxSignatures: s.receivedTxSignatures,
		localSpliceLocked: s.localSpliceLocked,
		remoteSpliceLocked: s.remoteSpliceLocked,
		confirmed: s.confirmed,
		confirmedHeight: s.confirmedHeight,
		lockAtDepth: s.lockAtDepth,
		conflict: s.conflict ? { ...s.conflict } : undefined
	};
}

export interface ISerializedV2InFlight {
	fundingTxid: string;
	fundingOutputIndex: number;
	fundingTxHex: string;
	fullySigned: boolean;
	isInitiator: boolean;
	localContributionSats: string;
	remoteContributionSats: string;
	fundingFeeratePerkw: number;
	weSignFirst: boolean;
	ourWitnesses: string[][];
	ourWalletInputIndices: number[];
	// Issue #554: tx-input indices of externally owned inputs whose witnesses
	// arrive out of band; absent on records without external inputs.
	externalInputIndices?: number[];
	inputPrevouts?: Array<{ script: string; valueSats: string }>;
	remoteCommitmentSig: string | null;
	sentTxSignatures: boolean;
	receivedTxSignatures: boolean;
	confirmed?: boolean;
	rbfAttempt: number;
	/**
	 * Per-attempt channel values (see IV2InFlight). Absent on rows written
	 * before contribution-changing RBF existed; localChannelReserveSatoshis is
	 * additionally absent on rows written before the v2 open derived it.
	 */
	fundingSatoshis?: string;
	localBalanceMsat?: string;
	remoteBalanceMsat?: string;
	remoteChannelReserveSatoshis?: string;
	localChannelReserveSatoshis?: string;
}

export function serializeV2InFlight(f: IV2InFlight): ISerializedV2InFlight {
	return {
		fundingTxid: f.fundingTxid.toString('hex'),
		fundingOutputIndex: f.fundingOutputIndex,
		fundingTxHex: f.fundingTxHex,
		fullySigned: f.fullySigned,
		isInitiator: f.isInitiator,
		localContributionSats: bigintToStr(f.localContributionSats),
		remoteContributionSats: bigintToStr(f.remoteContributionSats),
		fundingFeeratePerkw: f.fundingFeeratePerkw,
		weSignFirst: f.weSignFirst,
		ourWitnesses: f.ourWitnesses.map((w) => w.map((b) => b.toString('hex'))),
		ourWalletInputIndices: [...f.ourWalletInputIndices],
		externalInputIndices: f.externalInputIndices
			? [...f.externalInputIndices]
			: undefined,
		inputPrevouts: f.inputPrevouts.map((p) => ({
			script: p.script.toString('hex'),
			valueSats: bigintToStr(p.valueSats)
		})),
		remoteCommitmentSig: bufToHex(f.remoteCommitmentSig),
		sentTxSignatures: f.sentTxSignatures,
		receivedTxSignatures: f.receivedTxSignatures,
		confirmed: f.confirmed,
		rbfAttempt: f.rbfAttempt,
		fundingSatoshis:
			f.fundingSatoshis !== undefined
				? bigintToStr(f.fundingSatoshis)
				: undefined,
		localBalanceMsat:
			f.localBalanceMsat !== undefined
				? bigintToStr(f.localBalanceMsat)
				: undefined,
		remoteBalanceMsat:
			f.remoteBalanceMsat !== undefined
				? bigintToStr(f.remoteBalanceMsat)
				: undefined,
		remoteChannelReserveSatoshis:
			f.remoteChannelReserveSatoshis !== undefined
				? bigintToStr(f.remoteChannelReserveSatoshis)
				: undefined,
		localChannelReserveSatoshis:
			f.localChannelReserveSatoshis !== undefined
				? bigintToStr(f.localChannelReserveSatoshis)
				: undefined
	};
}

export function deserializeV2InFlight(s: ISerializedV2InFlight): IV2InFlight {
	return {
		fundingTxid: Buffer.from(s.fundingTxid, 'hex'),
		fundingOutputIndex: s.fundingOutputIndex,
		fundingTxHex: s.fundingTxHex,
		fullySigned: s.fullySigned,
		isInitiator: s.isInitiator,
		localContributionSats: strToBigint(s.localContributionSats),
		remoteContributionSats: strToBigint(s.remoteContributionSats),
		fundingFeeratePerkw: s.fundingFeeratePerkw,
		weSignFirst: s.weSignFirst,
		ourWitnesses: s.ourWitnesses.map((w) =>
			w.map((h) => Buffer.from(h, 'hex'))
		),
		ourWalletInputIndices: [...s.ourWalletInputIndices],
		externalInputIndices: s.externalInputIndices
			? [...s.externalInputIndices]
			: undefined,
		inputPrevouts: (s.inputPrevouts ?? []).map((p) => ({
			script: Buffer.from(p.script, 'hex'),
			valueSats: strToBigint(p.valueSats)
		})),
		remoteCommitmentSig: hexToBuf(s.remoteCommitmentSig),
		sentTxSignatures: s.sentTxSignatures,
		receivedTxSignatures: s.receivedTxSignatures,
		confirmed: s.confirmed ?? false,
		rbfAttempt: s.rbfAttempt,
		fundingSatoshis:
			s.fundingSatoshis !== undefined
				? strToBigint(s.fundingSatoshis)
				: undefined,
		localBalanceMsat:
			s.localBalanceMsat !== undefined
				? strToBigint(s.localBalanceMsat)
				: undefined,
		remoteBalanceMsat:
			s.remoteBalanceMsat !== undefined
				? strToBigint(s.remoteBalanceMsat)
				: undefined,
		remoteChannelReserveSatoshis:
			s.remoteChannelReserveSatoshis !== undefined
				? strToBigint(s.remoteChannelReserveSatoshis)
				: undefined,
		localChannelReserveSatoshis:
			s.localChannelReserveSatoshis !== undefined
				? strToBigint(s.localChannelReserveSatoshis)
				: undefined
	};
}

export function serializeChannelState(
	s: IChannelState,
	options: {
		legacyHtlcHistory?: boolean;
		/**
		 * Which revoked-commitment snapshots to write. Storage keeps them in
		 * a table of their own, so its channel row takes none and a journal
		 * delta only those not saved yet; a reader applies whatever it finds
		 * as additions to that table.
		 */
		htlcHistory?: 'all' | 'unsaved' | 'none';
		/**
		 * Journal a pending update_add_htlc of ours without the onion its
		 * offered HTLC entry already holds. Only recovery frames of version 4
		 * may carry that form.
		 */
		addOnionsByReference?: boolean;
	} = {}
): ISerializedChannelState {
	const htlcs: ISerializedHtlcEntry[] = [];
	for (const [key, entry] of s.htlcs) {
		htlcs.push(serializeHtlcEntry(key, entry));
	}

	const history =
		options.htlcHistory === 'none'
			? undefined
			: options.htlcHistory === 'unsaved'
			? unsavedRevokedHtlcSnapshots(s)
			: s.revokedHtlcSnapshots;
	let revokedHtlcSnapshots: ISerializedHtlcSnapshot[] | undefined;
	const compactHistory =
		!options.legacyHtlcHistory && usesCompactHtlcHistory(s);
	if (!compactHistory && history && history.size > 0) {
		revokedHtlcSnapshots = [];
		for (const [commitmentNumber, entries] of history) {
			revokedHtlcSnapshots.push({
				commitmentNumber,
				htlcs: serializeHtlcSnapshotEntries(entries)
			});
		}
	}

	return {
		channelId: bufToHex(s.channelId),
		temporaryChannelId: s.temporaryChannelId.toString('hex'),
		role: s.role,
		state: s.state,
		fundingSatoshis: bigintToStr(s.fundingSatoshis),
		pushMsat: bigintToStr(s.pushMsat),
		fundingTxid: bufToHex(s.fundingTxid),
		pendingFundingTxHex: s.pendingFundingTxHex,
		fundingTxHex: s.fundingTxHex,
		fundingMissingSinceHeight: s.fundingMissingSinceHeight,
		fundingUnaccounted: s.fundingUnaccounted,
		hasBeenSpliced: s.hasBeenSpliced,
		previousFundingTxids: s.previousFundingTxids?.map((t) => t.toString('hex')),
		lockedFundingTxids: s.lockedFundingTxids?.map((t) => t.toString('hex')),
		fundingOutputIndex: s.fundingOutputIndex,
		minimumDepth: s.minimumDepth,
		localConfig: serializeChannelConfig(s.localConfig),
		localBasepoints: serializeBasepoints(s.localBasepoints),
		localPerCommitmentSeed: s.localPerCommitmentSeed.toString('hex'),
		remoteConfig: serializeChannelConfig(s.remoteConfig),
		remoteBasepoints: s.remoteBasepoints
			? serializeBasepoints(s.remoteBasepoints)
			: null,
		localCommitmentNumber: bigintToStr(s.localCommitmentNumber),
		remoteCommitmentNumber: bigintToStr(s.remoteCommitmentNumber),
		remoteRevocationNumber:
			s.remoteRevocationNumber !== undefined
				? bigintToStr(s.remoteRevocationNumber)
				: undefined,
		needsCommitment: s.needsCommitment,
		pendingFeeratePerKw: s.pendingFeeratePerKw,
		pendingFeerateSignable: s.pendingFeerateSignable,
		pendingFeerateCommitted: s.pendingFeerateCommitted,
		awaitingLocalFeeCommitment: s.awaitingLocalFeeCommitment,
		lastSignedCommitFeeratePerKw: s.lastSignedCommitFeeratePerKw,
		pendingLeaseBlockheight: s.pendingLeaseBlockheight,
		pendingLeaseBlockheightSignable: s.pendingLeaseBlockheightSignable,
		pendingLeaseBlockheightCommitted: s.pendingLeaseBlockheightCommitted,
		lastSignedCommitLeaseBlockheight: s.lastSignedCommitLeaseBlockheight,
		leaseHeightHistory: s.leaseHeightHistory,
		localBalanceMsat: bigintToStr(s.localBalanceMsat),
		remoteBalanceMsat: bigintToStr(s.remoteBalanceMsat),
		shaChainData: serializeShaChainEntries(s.shaChainStore),
		remoteCurrentPerCommitmentPoint: bufToHex(
			s.remoteCurrentPerCommitmentPoint
		),
		remoteNextPerCommitmentPoint: bufToHex(s.remoteNextPerCommitmentPoint),
		localHtlcCounter: bigintToStr(s.localHtlcCounter),
		htlcs,
		signedLocalRemovals: s.signedLocalRemovals?.length
			? s.signedLocalRemovals.map((e) =>
					serializeHtlcEntry(`received-${e.id}`, e)
			  )
			: undefined,
		revokedHtlcSnapshots,
		...(compactHistory
			? { compactHtlcHistory: encodeHtlcHistory(history) }
			: {}),
		watchtowerRemoteCommitmentTxs: s.watchtowerRemoteCommitmentTxs?.size
			? [...s.watchtowerRemoteCommitmentTxs].flatMap(([point, txs]) =>
					txs.map((tx) => ({ point, tx: tx.toString('hex') }))
			  )
			: undefined,
		watchtowerBackupsOwed: s.watchtowerBackupsOwed?.length
			? s.watchtowerBackupsOwed.map((e) => ({
					secret: e.perCommitmentSecret.toString('hex'),
					tx: e.tx.toString('hex')
			  }))
			: undefined,
		remoteCommitmentSignature: bufToHex(s.remoteCommitmentSignature),
		remoteHtlcSignatures: s.remoteHtlcSignatures.map((b) => b.toString('hex')),
		remoteSigningNonce: bufToHex(s.remoteSigningNonce ?? null),
		channelType: bufToHex(s.channelType),
		localChannelReady: s.localChannelReady,
		remoteChannelReady: s.remoteChannelReady,
		condemned: s.condemned === true ? true : undefined,
		localShutdownScript: bufToHex(s.localShutdownScript),
		remoteShutdownScript: bufToHex(s.remoteShutdownScript),
		lastSentCommitmentSigned: bufToHex(s.lastSentCommitmentSigned),
		lastSentPartialSignatureWithNonce: bufToHex(
			s.lastSentPartialSignatureWithNonce
		),
		pendingLocalUpdates: (s.pendingLocalUpdates ?? []).map((u) => {
			const rest = options.addOnionsByReference
				? addWithoutOnion(s.htlcs, u.type, u.payload)
				: null;
			return rest
				? {
						type: u.type,
						payloadHex: rest.toString('hex'),
						onionFromHtlc: true as const
				  }
				: { type: u.type, payloadHex: u.payload.toString('hex') };
		}),
		pendingLocalUpdatesSignedCount: s.pendingLocalUpdatesSignedCount ?? 0,
		lastSentHtlcSignatures: s.lastSentHtlcSignatures.map((b) =>
			b.toString('hex')
		),
		lastSentRevokeSecret: bufToHex(s.lastSentRevokeSecret),
		lastSentRevokeNextPoint: bufToHex(s.lastSentRevokeNextPoint),
		lastSentWasRevoke: s.lastSentWasRevoke,
		preReestablishState: s.preReestablishState,
		lastProposedClosingFeeSat:
			s.lastProposedClosingFeeSat !== null
				? bigintToStr(s.lastProposedClosingFeeSat)
				: null,
		closingFeeMin:
			s.closingFeeMin !== null ? bigintToStr(s.closingFeeMin) : null,
		closingFeeMax:
			s.closingFeeMax !== null ? bigintToStr(s.closingFeeMax) : null,
		theirLastClosingFeeSat:
			s.theirLastClosingFeeSat !== null
				? bigintToStr(s.theirLastClosingFeeSat)
				: null,
		simpleClose: s.simpleClose,
		lastCloseFeeSat: s.lastLocalClosingComplete
			? bigintToStr(s.lastLocalClosingComplete.feeSatoshis)
			: null,
		lastCloseLocktime: s.lastLocalClosingComplete?.locktime ?? null,
		lastCloseCloserScript: s.lastLocalClosingComplete
			? s.lastLocalClosingComplete.closerScript.toString('hex')
			: null,
		lastCloseCloseeScript: s.lastLocalClosingComplete
			? s.lastLocalClosingComplete.closeeScript.toString('hex')
			: null,
		lastCloseSentVariants: s.lastLocalClosingComplete
			? s.lastLocalClosingComplete.sentVariants
			: null,
		shortChannelId: bufToHex(s.shortChannelId),
		fundingConfirmationHeight: s.fundingConfirmationHeight,
		fundingBroadcastHeight: s.fundingBroadcastHeight,
		fundingTxIndex: s.fundingTxIndex,
		announcementSigsSent: s.announcementSigsSent,
		announcementSigsReceived: s.announcementSigsReceived,
		remoteAnnouncementNodeSig: bufToHex(s.remoteAnnouncementNodeSig),
		remoteAnnouncementBitcoinSig: bufToHex(s.remoteAnnouncementBitcoinSig),
		localAnnouncementNodeSig: bufToHex(s.localAnnouncementNodeSig),
		localAnnouncementBitcoinSig: bufToHex(s.localAnnouncementBitcoinSig),
		announceChannel: s.announceChannel,
		scidAlias: bufToHex(s.scidAlias),
		remoteScidAlias: bufToHex(s.remoteScidAlias),
		zeroConfEnabled: s.zeroConfEnabled,
		trustedPeer: s.trustedPeer,
		quiescenceState: s.quiescenceState,
		quiescenceInitiator: s.quiescenceInitiator,
		spliceFundingTxid: bufToHex(s.spliceFundingTxid),
		spliceFundingOutputIndex: s.spliceFundingOutputIndex,
		preSpliceState: s.preSpliceState as string | null,
		spliceInFlight: s.spliceInFlight
			? serializeSpliceInFlight(s.spliceInFlight)
			: null,
		closeSpendsSpliceTxid: bufToHex(s.closeSpendsSpliceTxid),
		closeSpendsFundingTxid: s.closeSpendsFundingTxid?.toString('hex'),
		unconfirmedSpliceTxs: s.unconfirmedSpliceTxs?.length
			? s.unconfirmedSpliceTxs.map((e) => ({
					txid: e.txid.toString('hex'),
					txHex: e.txHex
			  }))
			: undefined,
		revertedSplices: s.revertedSplices?.length
			? s.revertedSplices.map((r) => ({
					...r,
					remoteHtlcSignatures: r.remoteHtlcSignatures
						? [...r.remoteHtlcSignatures]
						: undefined
			  }))
			: undefined,
		spliceAbortOwed: s.spliceAbortOwed === true ? true : undefined,
		remoteForwardingPolicy: s.remoteForwardingPolicy
			? {
					feeBaseMsat: s.remoteForwardingPolicy.feeBaseMsat,
					feeProportionalMillionths:
						s.remoteForwardingPolicy.feeProportionalMillionths,
					cltvExpiryDelta: s.remoteForwardingPolicy.cltvExpiryDelta,
					htlcMinimumMsat: s.remoteForwardingPolicy.htlcMinimumMsat.toString(),
					htlcMaximumMsat:
						s.remoteForwardingPolicy.htlcMaximumMsat === null
							? null
							: s.remoteForwardingPolicy.htlcMaximumMsat.toString(),
					timestamp: s.remoteForwardingPolicy.timestamp
			  }
			: null,
		fundingVersion: s.fundingVersion,
		channelReserveVersion: s.channelReserveVersion,
		localReserveWaived: s.localReserveWaived === true ? true : undefined,
		remoteReserveWaived: s.remoteReserveWaived === true ? true : undefined,
		commitmentFeeratePerkw: s.commitmentFeeratePerkw,
		fundingLocktime: s.fundingLocktime,
		v2InFlight: s.v2InFlight ? serializeV2InFlight(s.v2InFlight) : null,
		v2PreviousAttempts: s.v2PreviousAttempts?.length
			? s.v2PreviousAttempts.map(serializeV2InFlight)
			: undefined,
		isLessor: s.isLessor,
		leaseExpiry: s.leaseExpiry,
		leaseCommitBlockheight: s.leaseCommitBlockheight,
		lastCooperativeCloseTxHex: s.lastCooperativeCloseTxHex,
		externalClose: s.externalClose,
		dataLossDetected: s.dataLossDetected,
		fundingConfirmedLate: s.fundingConfirmedLate,
		stateUncertain: s.stateUncertain,
		restoreRecencyUnproven: s.restoreRecencyUnproven,
		reestablishRecencyUnproven: s.reestablishRecencyUnproven,
		reestablishSecretMissing: s.reestablishSecretMissing,
		restoreRevokedRisk: s.restoreRevokedRisk,
		staleCloseRiskAccepted: s.staleCloseRiskAccepted,
		preSpliceSpendWatches: s.preSpliceSpendWatches?.length
			? s.preSpliceSpendWatches.map((w) => ({ ...w }))
			: undefined,
		recoveryCloseReason: s.recoveryCloseReason,
		closeReason: s.closeReason,
		dlpRemotePerCommitmentPoint: bufToHex(
			s.dlpRemotePerCommitmentPoint ?? null
		),
		ffor: s.ffor ? serializeFforEpoch(s.ffor) : null,
		fforUsedEpochIds: s.fforUsedEpochIds?.length
			? [...s.fforUsedEpochIds]
			: undefined,
		// Asset channels only. Conditional on purpose: a row without asset
		// state gains no key, so it and every recovery frame that carries it
		// hash as they did before asset channels existed.
		...serializeAssetChannelFields(s),
		...(s.lastSentAuxiliaryRecords
			? {
					lastSentAuxiliaryRecords: serializeCustomRecords(
						s.lastSentAuxiliaryRecords
					)
			  }
			: {})
	};
}

// ─── FFOR Variant D epoch record (docs/specs/ffor-offline-receive.md 7.5.5) ───

export interface ISerializedFforEpoch {
	role: string;
	state: number;
	epochId: string;
	params: {
		variant: number;
		budgetMsat: string;
		maxPayments: number;
		minPaymentMsat: string;
		settlementDeadline: number;
		voucherExpiry: number;
		feeBaseMsat: number;
		feeProportionalMillionths: number;
		escapeGranularityMsat: string;
		rPerCommitmentPoints: string[];
		voucherAmountsMsat: string[];
		witnessPeers?: string[];
		hashChain?: boolean;
		/** ff_init TLV 17 as requested; absent when the TLV was. */
		concurrentVersion?: number;
	};
	remoteNodeId: string;
	initWire: string;
	acceptWire: string | null;
	sCommitmentNumber: string | null;
	sHtlcIdBase: string | null;
	paymentHashes: string[];
	preimages: string[];
	tInit: string;
	tSetup: string | null;
	hBook: string | null;
	hCommit: string | null;
	hAct: string | null;
	epochStartHeight: number | null;
	activateWire: string | null;
	activateAckWire: string | null;
	closeWire: string | null;
	closeAckWire: string | null;
	syncRequestWire?: string;
	syncSnapshotWire?: string;
	syncConflictWire?: string;
	slotRedeemed?: boolean[];
	slotStates: string[];
	slotUpstream: (string | null)[];
	settledBitmap: string | null;
	knownPreimages: (string | null)[];
	voucherOutcomes?: ({
		outcome: 'fulfilled' | 'cancelled';
		localCommitmentNumber: string;
		remoteCommitmentNumber: string;
	} | null)[];
	/** Absent on records written before the field existed: no slot exposed. */
	exposedSlots?: boolean[];
	/** Absent on records written before the field existed: no issuer. */
	issuerProvisioned?: boolean;
	/** Absent on records written before D-R existed: no witnesses. */
	witnesses?: {
		witnessNodeId: string;
		mailboxId: string;
		fetchPrivkey: string;
		encPrivkey: string;
		retentionUntil: number;
		minReceipts: number;
		manifestWire: string;
		ackedAt: number | null;
	}[];
	closeProcessed: boolean;
	voucherRoundFailed: boolean;
	unwindOwed: boolean;
	abortReason: number | null;
	closeSent: boolean;
	activationMismatch: boolean;
	/**
	 * The selected profile (see IFforEpochRecord.concurrentVersion). Written
	 * only for a concurrent epoch, so a baseline record serializes to the
	 * bytes it always did; absent reads as baseline.
	 */
	concurrentVersion?: number;
	concurrentVersionMismatch?: boolean;
	/**
	 * The capability hold (see IFforEpochRecord.capabilityHold). Written
	 * only while it stands, and only a concurrent epoch has one.
	 */
	capabilityHold?: boolean;
}

export function serializeFforEpoch(f: IFforEpochRecord): ISerializedFforEpoch {
	return {
		role: f.role,
		state: f.state,
		epochId: f.epochId.toString('hex'),
		params: {
			variant: f.params.variant,
			budgetMsat: bigintToStr(f.params.budgetMsat),
			maxPayments: f.params.maxPayments,
			minPaymentMsat: bigintToStr(f.params.minPaymentMsat),
			settlementDeadline: f.params.settlementDeadline,
			voucherExpiry: f.params.voucherExpiry,
			feeBaseMsat: f.params.feeBaseMsat,
			feeProportionalMillionths: f.params.feeProportionalMillionths,
			escapeGranularityMsat: bigintToStr(f.params.escapeGranularityMsat),
			rPerCommitmentPoints: f.params.rPerCommitmentPoints.map((p) =>
				p.toString('hex')
			),
			voucherAmountsMsat: f.params.voucherAmountsMsat.map(bigintToStr),
			...(f.params.witnessPeers
				? { witnessPeers: f.params.witnessPeers.map((p) => p.toString('hex')) }
				: {}),
			...(f.params.hashChain ? { hashChain: true } : {}),
			...(f.params.concurrentVersion !== undefined
				? { concurrentVersion: f.params.concurrentVersion }
				: {})
		},
		remoteNodeId: f.remoteNodeId.toString('hex'),
		initWire: f.initWire.toString('hex'),
		acceptWire: bufToHex(f.acceptWire),
		sCommitmentNumber:
			f.sCommitmentNumber === null ? null : bigintToStr(f.sCommitmentNumber),
		sHtlcIdBase: f.sHtlcIdBase === null ? null : bigintToStr(f.sHtlcIdBase),
		paymentHashes: f.paymentHashes.map((h) => h.toString('hex')),
		preimages: f.preimages.map((p) => p.toString('hex')),
		tInit: f.tInit.toString('hex'),
		tSetup: bufToHex(f.tSetup),
		hBook: bufToHex(f.hBook),
		hCommit: bufToHex(f.hCommit),
		hAct: bufToHex(f.hAct),
		epochStartHeight: f.epochStartHeight,
		activateWire: bufToHex(f.activateWire),
		activateAckWire: bufToHex(f.activateAckWire),
		closeWire: bufToHex(f.closeWire),
		closeAckWire: bufToHex(f.closeAckWire),
		...(f.syncRequestWire
			? { syncRequestWire: f.syncRequestWire.toString('hex') }
			: {}),
		...(f.syncSnapshotWire
			? { syncSnapshotWire: f.syncSnapshotWire.toString('hex') }
			: {}),
		...(f.syncConflictWire
			? { syncConflictWire: f.syncConflictWire.toString('hex') }
			: {}),
		...(f.slotRedeemed ? { slotRedeemed: [...f.slotRedeemed] } : {}),
		slotStates: [...f.slotStates],
		slotUpstream: [...f.slotUpstream],
		settledBitmap: bufToHex(f.settledBitmap),
		knownPreimages: f.knownPreimages.map((p) => bufToHex(p)),
		...(f.voucherOutcomes
			? {
					voucherOutcomes: f.voucherOutcomes.map((o) =>
						o
							? {
									outcome: o.outcome,
									localCommitmentNumber: bigintToStr(o.localCommitmentNumber),
									remoteCommitmentNumber: bigintToStr(o.remoteCommitmentNumber)
							  }
							: null
					)
			  }
			: {}),
		exposedSlots: [...f.exposedSlots],
		issuerProvisioned: f.issuerProvisioned,
		witnesses: f.witnesses.map((w) => ({
			witnessNodeId: w.witnessNodeId.toString('hex'),
			mailboxId: w.mailboxId.toString('hex'),
			fetchPrivkey: w.fetchPrivkey.toString('hex'),
			encPrivkey: w.encPrivkey.toString('hex'),
			retentionUntil: w.retentionUntil,
			minReceipts: w.minReceipts,
			manifestWire: w.manifestWire.toString('hex'),
			ackedAt: w.ackedAt
		})),
		closeProcessed: f.closeProcessed,
		voucherRoundFailed: f.voucherRoundFailed,
		unwindOwed: f.unwindOwed,
		abortReason: f.abortReason,
		closeSent: f.closeSent,
		activationMismatch: f.activationMismatch,
		...(f.concurrentVersionMismatch ? { concurrentVersionMismatch: true } : {}),
		...(isFforConcurrentVersion(f.concurrentVersion)
			? { concurrentVersion: f.concurrentVersion }
			: {}),
		...(isFforConcurrentVersion(f.concurrentVersion) &&
		f.capabilityHold === true
			? { capabilityHold: true }
			: {})
	};
}

/**
 * The selected profile of a stored epoch, checked against the transcript
 * it was persisted with (docs/specs/CONCURRENT-RECEIVE.md section 1.1: the
 * version is never inferred from features, connection status or preferences,
 * and section 8: it is compared with the persisted setup bytes).
 *
 * The stored field and the stored ff_init and ff_accept must tell one
 * story: a request and its exact echo beside a selected version, or no
 * TLV 17 in either beside none. When they do not (a row a build without
 * the field rewrote, a damaged row), the record is never read as a
 * baseline epoch: it is concurrent if either source says so, and
 * `mismatch` is set so the caller raises activationMismatch, which stops
 * new work on both sides and leaves the vouchers and every existing
 * obligation in place. A record whose wires do not decode and whose field
 * is absent is left alone; there is nothing to compare.
 */
function storedConcurrentVersion(
	storedField: number | undefined,
	requestedField: number | undefined,
	initWire: Buffer,
	acceptWire: Buffer | null
): { selected: 0 | FforConcurrentVersion; mismatch: boolean } {
	const stored = isFforConcurrentVersion(storedField) ? storedField : 0;
	const transcript = fforTranscriptConcurrentVersion(initWire, acceptWire);
	if (transcript === null) {
		const hints = [storedField, requestedField].filter(
			(version) => version !== undefined && version !== 0
		);
		return {
			selected:
				hints.some((version) => version !== 1) || requestedField === 0
					? 2
					: hints.length
					? 1
					: 0,
			mismatch: !!storedField || requestedField !== undefined
		};
	}
	const { requested, echoed } = transcript;
	const accepted = acceptWire !== null;
	const selectedOnWire =
		accepted && isFforConcurrentVersion(requested) && echoed === requested
			? requested
			: 0;
	const unsupported =
		(storedField !== undefined &&
			storedField !== 0 &&
			!isFforConcurrentVersion(storedField)) ||
		[requestedField, requested, echoed].some(
			(version) => version !== undefined && !isFforConcurrentVersion(version)
		);
	const consistent =
		!unsupported &&
		selectedOnWire === stored &&
		requested === requestedField &&
		(!accepted || echoed === requested);
	// Never reinterpret a contradictory or unknown selected version as baseline.
	// Prefer the reservation-preserving profile while the mismatch quarantines it.
	const selected =
		unsupported ||
		stored === 2 ||
		selectedOnWire === 2 ||
		(!consistent && [requestedField, requested, echoed].includes(2))
			? 2
			: stored || selectedOnWire;
	return { selected, mismatch: !consistent };
}

export function deserializeFforEpoch(
	s: ISerializedFforEpoch
): IFforEpochRecord {
	for (const wire of [
		s.syncRequestWire,
		s.syncSnapshotWire,
		s.syncConflictWire
	]) {
		if (
			wire !== undefined &&
			(typeof wire !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(wire))
		)
			throw new Error('Invalid persisted receipt wire encoding');
	}
	const initWire = Buffer.from(s.initWire, 'hex');
	const acceptWire = hexToBuf(s.acceptWire);
	const concurrent = storedConcurrentVersion(
		s.concurrentVersion,
		s.params.concurrentVersion,
		initWire,
		acceptWire
	);
	const record: IFforEpochRecord = {
		role: s.role as FforRole,
		state: s.state as FforState,
		epochId: Buffer.from(s.epochId, 'hex'),
		params: {
			variant: s.params.variant,
			budgetMsat: strToBigint(s.params.budgetMsat),
			maxPayments: s.params.maxPayments,
			minPaymentMsat: strToBigint(s.params.minPaymentMsat),
			settlementDeadline: s.params.settlementDeadline,
			voucherExpiry: s.params.voucherExpiry,
			feeBaseMsat: s.params.feeBaseMsat,
			feeProportionalMillionths: s.params.feeProportionalMillionths,
			escapeGranularityMsat: strToBigint(s.params.escapeGranularityMsat),
			rPerCommitmentPoints: s.params.rPerCommitmentPoints.map((p) =>
				Buffer.from(p, 'hex')
			),
			voucherAmountsMsat: s.params.voucherAmountsMsat.map(strToBigint),
			...(s.params.witnessPeers
				? {
						witnessPeers: s.params.witnessPeers.map((p) =>
							Buffer.from(p, 'hex')
						)
				  }
				: {}),
			...(s.params.hashChain ? { hashChain: true } : {}),
			...(s.params.concurrentVersion !== undefined
				? { concurrentVersion: s.params.concurrentVersion }
				: {})
		},
		remoteNodeId: Buffer.from(s.remoteNodeId, 'hex'),
		initWire,
		acceptWire,
		sCommitmentNumber:
			s.sCommitmentNumber === null ? null : strToBigint(s.sCommitmentNumber),
		sHtlcIdBase: s.sHtlcIdBase === null ? null : strToBigint(s.sHtlcIdBase),
		paymentHashes: s.paymentHashes.map((h) => Buffer.from(h, 'hex')),
		preimages: s.preimages.map((p) => Buffer.from(p, 'hex')),
		tInit: Buffer.from(s.tInit, 'hex'),
		tSetup: hexToBuf(s.tSetup),
		hBook: hexToBuf(s.hBook),
		hCommit: hexToBuf(s.hCommit),
		hAct: hexToBuf(s.hAct),
		epochStartHeight: s.epochStartHeight,
		activateWire: hexToBuf(s.activateWire),
		activateAckWire: hexToBuf(s.activateAckWire),
		closeWire: hexToBuf(s.closeWire),
		closeAckWire: hexToBuf(s.closeAckWire),
		...(s.syncRequestWire
			? { syncRequestWire: Buffer.from(s.syncRequestWire, 'hex') }
			: {}),
		...(s.syncSnapshotWire
			? { syncSnapshotWire: Buffer.from(s.syncSnapshotWire, 'hex') }
			: {}),
		...(s.syncConflictWire
			? { syncConflictWire: Buffer.from(s.syncConflictWire, 'hex') }
			: {}),
		...(s.slotRedeemed ? { slotRedeemed: [...s.slotRedeemed] } : {}),
		slotStates: s.slotStates.map((x) => x as FforSlotState),
		slotUpstream: [...s.slotUpstream],
		settledBitmap: hexToBuf(s.settledBitmap),
		knownPreimages: s.knownPreimages.map((p) => hexToBuf(p)),
		...(s.voucherOutcomes
			? {
					voucherOutcomes: s.voucherOutcomes.map((o) => {
						if (o === null) return null;
						if (
							(o.outcome !== 'fulfilled' && o.outcome !== 'cancelled') ||
							!/^\d+$/.test(o.localCommitmentNumber) ||
							!/^\d+$/.test(o.remoteCommitmentNumber)
						)
							throw new Error('Invalid FFOR voucher outcome');
						return {
							outcome: o.outcome,
							localCommitmentNumber: strToBigint(o.localCommitmentNumber),
							remoteCommitmentNumber: strToBigint(o.remoteCommitmentNumber)
						};
					})
			  }
			: {}),
		exposedSlots: s.exposedSlots ?? s.knownPreimages.map(() => false),
		issuerProvisioned: s.issuerProvisioned === true,
		witnesses: (s.witnesses ?? []).map((w) => ({
			witnessNodeId: Buffer.from(w.witnessNodeId, 'hex'),
			mailboxId: Buffer.from(w.mailboxId, 'hex'),
			fetchPrivkey: Buffer.from(w.fetchPrivkey, 'hex'),
			encPrivkey: Buffer.from(w.encPrivkey, 'hex'),
			retentionUntil: w.retentionUntil,
			minReceipts: w.minReceipts,
			manifestWire: Buffer.from(w.manifestWire, 'hex'),
			ackedAt: w.ackedAt
		})),
		closeProcessed: s.closeProcessed === true,
		voucherRoundFailed: s.voucherRoundFailed === true,
		unwindOwed: s.unwindOwed === true,
		abortReason:
			s.abortReason === null || s.abortReason === undefined
				? null
				: (s.abortReason as FforAbortReason),
		closeSent: s.closeSent === true,
		activationMismatch: s.activationMismatch === true || concurrent.mismatch,
		...(s.concurrentVersionMismatch ||
		(concurrent.selected === 2 && concurrent.mismatch)
			? { concurrentVersionMismatch: true }
			: {}),
		...(isFforConcurrentVersion(concurrent.selected)
			? { concurrentVersion: concurrent.selected }
			: {}),
		...(isFforConcurrentVersion(concurrent.selected) &&
		s.capabilityHold === true
			? { capabilityHold: true }
			: {})
	};
	validateFforSyncState(record);
	return record;
}

export function deserializeChannelState(
	s: ISerializedChannelState
): IChannelState {
	const htlcs = new Map<string, IHtlcEntry>();
	for (const h of s.htlcs) {
		const { key, entry } = deserializeHtlcEntry(h);
		htlcs.set(key, entry);
	}

	let revokedHtlcSnapshots: Map<string, IHtlcSnapshotEntry[]> | undefined;
	if (s.compactHtlcHistory !== undefined) {
		if (s.revokedHtlcSnapshots !== undefined)
			throw new Error('Conflicting HTLC history encodings');
		revokedHtlcSnapshots = decodeHtlcHistory(s.compactHtlcHistory);
	}
	if (s.revokedHtlcSnapshots && s.revokedHtlcSnapshots.length > 0) {
		revokedHtlcSnapshots = new Map();
		for (const snap of s.revokedHtlcSnapshots) {
			revokedHtlcSnapshots.set(
				snap.commitmentNumber,
				deserializeHtlcSnapshotEntries(snap.htlcs)
			);
		}
	}

	return {
		channelId: hexToBuf(s.channelId),
		temporaryChannelId: Buffer.from(s.temporaryChannelId, 'hex'),
		role: s.role as ChannelRole,
		state: s.state as ChannelState,
		fundingSatoshis: strToBigint(s.fundingSatoshis),
		pushMsat: strToBigint(s.pushMsat),
		fundingTxid: hexToBuf(s.fundingTxid),
		pendingFundingTxHex: s.pendingFundingTxHex,
		fundingTxHex: s.fundingTxHex,
		fundingMissingSinceHeight: s.fundingMissingSinceHeight,
		fundingUnaccounted: s.fundingUnaccounted,
		hasBeenSpliced: s.hasBeenSpliced,
		previousFundingTxids: s.previousFundingTxids?.map((t) =>
			Buffer.from(t, 'hex')
		),
		lockedFundingTxids: s.lockedFundingTxids?.map((t) => Buffer.from(t, 'hex')),
		fundingOutputIndex: s.fundingOutputIndex,
		minimumDepth: s.minimumDepth,
		localConfig: deserializeChannelConfig(s.localConfig),
		localBasepoints: deserializeBasepoints(s.localBasepoints),
		localPerCommitmentSeed: Buffer.from(s.localPerCommitmentSeed, 'hex'),
		remoteConfig: s.remoteConfig
			? deserializeChannelConfig(s.remoteConfig)
			: { ...DEFAULT_CHANNEL_CONFIG },
		remoteBasepoints: s.remoteBasepoints
			? deserializeBasepoints(s.remoteBasepoints)
			: null,
		localCommitmentNumber: strToBigint(s.localCommitmentNumber),
		remoteCommitmentNumber: strToBigint(s.remoteCommitmentNumber),
		remoteRevocationNumber:
			s.remoteRevocationNumber !== undefined
				? strToBigint(s.remoteRevocationNumber)
				: undefined,
		needsCommitment: s.needsCommitment ?? false,
		pendingFeeratePerKw: s.pendingFeeratePerKw,
		pendingFeerateSignable: s.pendingFeerateSignable,
		pendingFeerateCommitted: s.pendingFeerateCommitted,
		awaitingLocalFeeCommitment: s.awaitingLocalFeeCommitment,
		lastSignedCommitFeeratePerKw: s.lastSignedCommitFeeratePerKw,
		pendingLeaseBlockheight: s.pendingLeaseBlockheight,
		pendingLeaseBlockheightSignable: s.pendingLeaseBlockheightSignable,
		pendingLeaseBlockheightCommitted: s.pendingLeaseBlockheightCommitted,
		lastSignedCommitLeaseBlockheight: s.lastSignedCommitLeaseBlockheight,
		leaseHeightHistory: s.leaseHeightHistory,
		localBalanceMsat: strToBigint(s.localBalanceMsat),
		remoteBalanceMsat: strToBigint(s.remoteBalanceMsat),
		shaChainStore: deserializeShaChainStore(s.shaChainData),
		remoteCurrentPerCommitmentPoint: hexToBuf(
			s.remoteCurrentPerCommitmentPoint
		),
		remoteNextPerCommitmentPoint: hexToBuf(s.remoteNextPerCommitmentPoint),
		localHtlcCounter: strToBigint(s.localHtlcCounter),
		htlcs,
		signedLocalRemovals: s.signedLocalRemovals?.length
			? s.signedLocalRemovals.map((h) => deserializeHtlcEntry(h).entry)
			: undefined,
		revokedHtlcSnapshots,
		...(s.compactHtlcHistory !== undefined ||
		isFforConcurrentVersion(s.ffor?.concurrentVersion)
			? { compactHtlcHistory: true as const }
			: {}),
		watchtowerRemoteCommitmentTxs: s.watchtowerRemoteCommitmentTxs?.length
			? s.watchtowerRemoteCommitmentTxs.reduce(
					(cache, e) =>
						cache.set(e.point, [
							...(cache.get(e.point) ?? []),
							Buffer.from(e.tx, 'hex')
						]),
					new Map<string, Buffer[]>()
			  )
			: undefined,
		watchtowerBackupsOwed: s.watchtowerBackupsOwed?.length
			? s.watchtowerBackupsOwed.map((e) => ({
					perCommitmentSecret: Buffer.from(e.secret, 'hex'),
					tx: Buffer.from(e.tx, 'hex')
			  }))
			: undefined,
		remoteCommitmentSignature: hexToBuf(s.remoteCommitmentSignature),
		remoteHtlcSignatures: s.remoteHtlcSignatures.map((h) =>
			Buffer.from(h, 'hex')
		),
		remoteSigningNonce: hexToBuf(s.remoteSigningNonce) ?? undefined,
		channelType: hexToBuf(s.channelType),
		localChannelReady: s.localChannelReady,
		remoteChannelReady: s.remoteChannelReady,
		condemned: s.condemned === true ? true : undefined,
		localShutdownScript: hexToBuf(s.localShutdownScript),
		remoteShutdownScript: hexToBuf(s.remoteShutdownScript),
		lastSentCommitmentSigned: hexToBuf(s.lastSentCommitmentSigned),
		lastSentPartialSignatureWithNonce: hexToBuf(
			s.lastSentPartialSignatureWithNonce
		),
		pendingLocalUpdates: (s.pendingLocalUpdates ?? []).map((u) => ({
			type: u.type,
			payload:
				u.onionFromHtlc === true
					? restoreAddOnion(htlcs, u.type, u.payloadHex)
					: Buffer.from(u.payloadHex, 'hex')
		})),
		pendingLocalUpdatesSignedCount: s.pendingLocalUpdatesSignedCount ?? 0,
		lastSentHtlcSignatures: (s.lastSentHtlcSignatures || []).map((h) =>
			Buffer.from(h, 'hex')
		),
		lastSentRevokeSecret: hexToBuf(s.lastSentRevokeSecret),
		lastSentRevokeNextPoint: hexToBuf(s.lastSentRevokeNextPoint),
		lastSentWasRevoke: s.lastSentWasRevoke ?? null,
		preReestablishState: (s.preReestablishState as ChannelState) || null,
		lastProposedClosingFeeSat:
			s.lastProposedClosingFeeSat !== null
				? strToBigint(s.lastProposedClosingFeeSat)
				: null,
		closingFeeMin:
			s.closingFeeMin !== null ? strToBigint(s.closingFeeMin) : null,
		closingFeeMax:
			s.closingFeeMax !== null ? strToBigint(s.closingFeeMax) : null,
		theirLastClosingFeeSat:
			s.theirLastClosingFeeSat !== null
				? strToBigint(s.theirLastClosingFeeSat)
				: null,
		simpleClose: s.simpleClose ?? null,
		lastLocalClosingComplete:
			s.lastCloseFeeSat != null &&
			s.lastCloseLocktime != null &&
			s.lastCloseCloserScript != null &&
			s.lastCloseCloseeScript != null
				? {
						feeSatoshis: strToBigint(s.lastCloseFeeSat),
						locktime: s.lastCloseLocktime,
						closerScript: Buffer.from(s.lastCloseCloserScript, 'hex'),
						closeeScript: Buffer.from(s.lastCloseCloseeScript, 'hex'),
						sentVariants: s.lastCloseSentVariants ?? []
				  }
				: null,
		// Not persisted by design: reconnection restarts simple-close negotiation.
		awaitingClosingSig: false,
		shortChannelId: hexToBuf(s.shortChannelId),
		fundingConfirmationHeight: s.fundingConfirmationHeight || 0,
		fundingBroadcastHeight: s.fundingBroadcastHeight ?? 0,
		fundingTxIndex: s.fundingTxIndex || 0,
		announcementSigsSent: s.announcementSigsSent || false,
		announcementSigsReceived: s.announcementSigsReceived || false,
		remoteAnnouncementNodeSig: hexToBuf(s.remoteAnnouncementNodeSig),
		remoteAnnouncementBitcoinSig: hexToBuf(s.remoteAnnouncementBitcoinSig),
		localAnnouncementNodeSig: hexToBuf(s.localAnnouncementNodeSig),
		localAnnouncementBitcoinSig: hexToBuf(s.localAnnouncementBitcoinSig),
		announceChannel: s.announceChannel ?? true,
		scidAlias: hexToBuf(s.scidAlias),
		remoteScidAlias: hexToBuf(s.remoteScidAlias),
		zeroConfEnabled: s.zeroConfEnabled ?? false,
		trustedPeer: s.trustedPeer ?? false,
		quiescenceState: s.quiescenceState ?? 'NORMAL',
		quiescenceInitiator: s.quiescenceInitiator ?? false,
		spliceFundingTxid: s.spliceFundingTxid
			? hexToBuf(s.spliceFundingTxid)
			: null,
		spliceFundingOutputIndex: s.spliceFundingOutputIndex ?? 0,
		preSpliceState: (s.preSpliceState as ChannelState) || null,
		spliceInFlight: s.spliceInFlight
			? deserializeSpliceInFlight(s.spliceInFlight)
			: null,
		closeSpendsSpliceTxid: s.closeSpendsSpliceTxid
			? hexToBuf(s.closeSpendsSpliceTxid)
			: null,
		closeSpendsFundingTxid: s.closeSpendsFundingTxid
			? Buffer.from(s.closeSpendsFundingTxid, 'hex')
			: undefined,
		unconfirmedSpliceTxs: s.unconfirmedSpliceTxs?.length
			? s.unconfirmedSpliceTxs.map((e) => ({
					txid: Buffer.from(e.txid, 'hex'),
					txHex: e.txHex
			  }))
			: [],
		revertedSplices: s.revertedSplices?.length
			? s.revertedSplices.map((r) => ({
					...r,
					remoteHtlcSignatures: r.remoteHtlcSignatures
						? [...r.remoteHtlcSignatures]
						: undefined
			  }))
			: [],
		spliceAbortOwed: s.spliceAbortOwed ?? false,
		remoteForwardingPolicy: s.remoteForwardingPolicy
			? {
					feeBaseMsat: s.remoteForwardingPolicy.feeBaseMsat,
					feeProportionalMillionths:
						s.remoteForwardingPolicy.feeProportionalMillionths,
					cltvExpiryDelta: s.remoteForwardingPolicy.cltvExpiryDelta,
					htlcMinimumMsat: BigInt(s.remoteForwardingPolicy.htlcMinimumMsat),
					htlcMaximumMsat:
						s.remoteForwardingPolicy.htlcMaximumMsat === null
							? null
							: BigInt(s.remoteForwardingPolicy.htlcMaximumMsat),
					timestamp: s.remoteForwardingPolicy.timestamp
			  }
			: null,
		fundingVersion: (s.fundingVersion ?? 1) as 1 | 2,
		channelReserveVersion: s.channelReserveVersion,
		localReserveWaived: s.localReserveWaived === true,
		remoteReserveWaived: s.remoteReserveWaived === true,
		dualFundingSession: null,
		commitmentFeeratePerkw: s.commitmentFeeratePerkw ?? 0,
		fundingLocktime: s.fundingLocktime ?? 0,
		v2InFlight: s.v2InFlight ? deserializeV2InFlight(s.v2InFlight) : null,
		v2PreviousAttempts: s.v2PreviousAttempts?.length
			? s.v2PreviousAttempts.map(deserializeV2InFlight)
			: undefined,
		isLessor: s.isLessor,
		leaseExpiry: s.leaseExpiry,
		leaseCommitBlockheight: s.leaseCommitBlockheight,
		lastCooperativeCloseTxHex: s.lastCooperativeCloseTxHex,
		externalClose: s.externalClose,
		dataLossDetected: s.dataLossDetected,
		fundingConfirmedLate: s.fundingConfirmedLate,
		stateUncertain: s.stateUncertain,
		restoreRecencyUnproven: s.restoreRecencyUnproven,
		reestablishRecencyUnproven: s.reestablishRecencyUnproven,
		reestablishSecretMissing: s.reestablishSecretMissing,
		restoreRevokedRisk: s.restoreRevokedRisk,
		staleCloseRiskAccepted: s.staleCloseRiskAccepted,
		preSpliceSpendWatches: s.preSpliceSpendWatches?.length
			? s.preSpliceSpendWatches.map((w) => ({ ...w }))
			: undefined,
		recoveryCloseReason: s.recoveryCloseReason,
		closeReason: s.closeReason,
		dlpRemotePerCommitmentPoint:
			hexToBuf(s.dlpRemotePerCommitmentPoint) ?? undefined,
		ffor: s.ffor ? deserializeFforEpoch(s.ffor) : null,
		fforUsedEpochIds: s.fforUsedEpochIds?.length
			? [...s.fforUsedEpochIds]
			: undefined,
		...(s.fundingTaprootMerkleRoot !== undefined
			? {
					fundingTaprootMerkleRoot: deserializeFundingTaprootMerkleRoot(
						s.fundingTaprootMerkleRoot
					)
			  }
			: {}),
		...(s.auxiliaryState !== undefined
			? { auxiliaryState: deserializeAuxiliaryState(s.auxiliaryState) }
			: {}),
		...(s.lastSentAuxiliaryRecords !== undefined
			? {
					lastSentAuxiliaryRecords: deserializeCustomRecords(
						s.lastSentAuxiliaryRecords
					)
			  }
			: {})
	};
}

/** A stored asset funding root: exactly 32 bytes of lowercase hex, or a throw. */
/**
 * The funding root and asset state of an asset channel, and no key at all
 * for any other channel. An asset channel is stored whole or not at all:
 * the overlay channel type, the funding root and the asset state are only
 * runnable together, so a state that has one without the others is refused
 * here, at the save, where the fault is, and not at the next start. Each
 * value goes through the reader's own checks for the same reason.
 */
function serializeAssetChannelFields(
	s: IChannelState
): Pick<
	ISerializedChannelState,
	'fundingTaprootMerkleRoot' | 'auxiliaryState'
> {
	if (
		s.auxiliaryState === undefined &&
		s.fundingTaprootMerkleRoot === undefined &&
		!isOverlayChannel(s.channelType)
	) {
		return {};
	}
	const id = (s.channelId ?? s.temporaryChannelId).toString('hex');
	if (!s.auxiliaryState || !s.fundingTaprootMerkleRoot) {
		throw new Error(
			`Refusing to store an incomplete asset channel (${id}): the overlay channel type, the funding root and the asset state go together`
		);
	}
	if (!Buffer.isBuffer(s.fundingTaprootMerkleRoot)) {
		throw new Error('Malformed asset funding root');
	}
	const fundingTaprootMerkleRoot = s.fundingTaprootMerkleRoot.toString('hex');
	deserializeFundingTaprootMerkleRoot(fundingTaprootMerkleRoot);
	return {
		fundingTaprootMerkleRoot,
		auxiliaryState: serializeAuxiliaryState(s.auxiliaryState)
	};
}

/** Whether a channel row, as the codec writes it, carries any mark of an asset channel. */
function channelRowCarriesAssetState(row: unknown): boolean {
	if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
	const fields = row as Record<string, unknown>;
	if (
		fields.auxiliaryState !== undefined ||
		fields.fundingTaprootMerkleRoot !== undefined
	) {
		return true;
	}
	return (
		typeof fields.channelType === 'string' &&
		/^(?:[0-9a-f]{2})+$/i.test(fields.channelType) &&
		isOverlayChannel(Buffer.from(fields.channelType, 'hex'))
	);
}

/**
 * The stored form of an asset channel's row: the row inside an envelope.
 *
 * A release from before asset channels reads a channel row field by field
 * and ignores keys it does not know, so it would load an asset channel as
 * an ordinary one and write it back without its asset state. It cannot
 * decode this envelope at all: it skips the row as corrupt, reports it and
 * leaves it as it is, and the channel is whole again under a release that
 * knows it.
 */
export interface IStoredAssetChannelRow {
	assetChannelRow: 1;
	channel: ISerializedChannelState;
}

/**
 * The form a channel row is stored in. A channel without asset state is
 * stored as the row it always was, byte for byte; an asset channel is
 * stored in its envelope (IStoredAssetChannelRow).
 */
export function channelRowToStore(
	row: ISerializedChannelState
): ISerializedChannelState | IStoredAssetChannelRow {
	return channelRowCarriesAssetState(row)
		? { assetChannelRow: 1, channel: row }
		: row;
}

/**
 * The channel row inside its stored form, or a throw. The reader takes
 * exactly what the writer makes: an envelope of this version around a row
 * of an asset channel, or a bare row of a channel that is not one. An
 * asset channel's row outside its envelope was written by nothing that
 * knows asset channels, and is refused.
 */
export function channelRowFromStore(stored: unknown): ISerializedChannelState {
	if (
		stored &&
		typeof stored === 'object' &&
		!Array.isArray(stored) &&
		'assetChannelRow' in stored
	) {
		const envelope = stored as Record<string, unknown>;
		if (
			envelope.assetChannelRow !== 1 ||
			Object.keys(envelope).length !== 2 ||
			!channelRowCarriesAssetState(envelope.channel)
		) {
			throw new Error('Malformed stored asset channel row');
		}
		return envelope.channel as ISerializedChannelState;
	}
	if (channelRowCarriesAssetState(stored)) {
		throw new Error('An asset channel row is stored without its envelope');
	}
	return stored as ISerializedChannelState;
}

/**
 * Whether a parsed channel row, stored or bare, belongs to an asset
 * channel, told from its keys alone and without decoding it. A loader that
 * skips rows it cannot decode uses this to tell an unreadable asset row
 * from any other, because an asset channel that is silently left out is
 * neither run nor watched.
 */
export function serializedChannelCarriesAssetState(row: unknown): boolean {
	if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
	return 'assetChannelRow' in row || channelRowCarriesAssetState(row);
}

function deserializeFundingTaprootMerkleRoot(hex: string): Buffer {
	if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) {
		throw new Error('Malformed serialized asset funding root');
	}
	return Buffer.from(hex, 'hex');
}

// ─── IPaymentInfo ───

export interface ISerializedPaymentInfo {
	payAll?: {
		debitMsat: string;
		maxFeeMsat: string;
		deliveredMsat: string;
		feeMsat: string;
		remainderMsat: string;
	};
	paymentHash: string;
	preimage?: string;
	amountMsat: string;
	/** Msat that left the node, fees included, when amountMsat is not that (MPP). */
	sentMsat?: string;
	/** Msat an incoming payment's settled HTLCs paid, when amountMsat is not that. */
	receivedMsat?: string;
	/** Carried by asset HTLCs; present only then. */
	auxiliary?: true;
	/** OUTGOING asset payment: what it is worth to the payee. */
	auxiliaryValueMsat?: string;
	status: string;
	direction: string;
	route?: string; // JSON string
	sharedSecrets?: string[]; // hex
	failureCode?: number;
	failureSourceIndex?: number;
	failureReason?: string;
	createdAt: number;
	completedAt?: number;
	settledHtlcs?: string[];
	metadata?: Record<string, string>;
}

export function serializePaymentInfo(p: IPaymentInfo): ISerializedPaymentInfo {
	return {
		...(p.payAll
			? {
					payAll: {
						debitMsat: p.payAll.debitMsat.toString(),
						maxFeeMsat: p.payAll.maxFeeMsat.toString(),
						deliveredMsat: p.payAll.deliveredMsat.toString(),
						feeMsat: p.payAll.feeMsat.toString(),
						remainderMsat: p.payAll.remainderMsat.toString()
					}
			  }
			: {}),
		paymentHash: p.paymentHash.toString('hex'),
		preimage: bufToHex(p.preimage) ?? undefined,
		amountMsat: bigintToStr(p.amountMsat),
		...(p.sentMsat !== undefined ? { sentMsat: bigintToStr(p.sentMsat) } : {}),
		...(p.receivedMsat !== undefined
			? { receivedMsat: bigintToStr(p.receivedMsat) }
			: {}),
		...(p.auxiliary === true ? { auxiliary: true as const } : {}),
		...(p.auxiliaryValueMsat !== undefined
			? { auxiliaryValueMsat: bigintToStr(p.auxiliaryValueMsat) }
			: {}),
		status: p.status,
		direction: p.direction,
		route: p.route
			? JSON.stringify(p.route, (_, v) =>
					typeof v === 'bigint'
						? `__bigint__${v.toString()}`
						: // Buffers reach the replacer already in toJSON form (see
						// serializeChainMonitorState); keep the isBuffer check as a fallback.
						isBufferJson(v)
						? `__buffer__${Buffer.from(v.data).toString('hex')}`
						: Buffer.isBuffer(v)
						? `__buffer__${v.toString('hex')}`
						: v
			  )
			: undefined,
		sharedSecrets: p.sharedSecrets?.map((b) => b.toString('hex')),
		failureCode: p.failureCode,
		failureSourceIndex: p.failureSourceIndex,
		failureReason: p.failureReason,
		createdAt: p.createdAt,
		completedAt: p.completedAt,
		settledHtlcs: p.settledHtlcs,
		metadata: p.metadata
	};
}

export function deserializePaymentInfo(
	s: ISerializedPaymentInfo
): IPaymentInfo {
	const reviver = (_: string, v: unknown): unknown => {
		if (typeof v === 'string' && v.startsWith('__bigint__'))
			return BigInt(v.slice(10));
		if (typeof v === 'string' && v.startsWith('__buffer__'))
			return Buffer.from(v.slice(10), 'hex');
		// Legacy rows persisted Buffers in raw toJSON form (replacer never saw them).
		if (isBufferJson(v)) return Buffer.from(v.data);
		return v;
	};

	return {
		...(s.payAll
			? {
					payAll: {
						debitMsat: BigInt(s.payAll.debitMsat),
						maxFeeMsat: BigInt(s.payAll.maxFeeMsat),
						deliveredMsat: BigInt(s.payAll.deliveredMsat),
						feeMsat: BigInt(s.payAll.feeMsat),
						remainderMsat: BigInt(s.payAll.remainderMsat)
					}
			  }
			: {}),
		paymentHash: Buffer.from(s.paymentHash, 'hex'),
		preimage: s.preimage ? Buffer.from(s.preimage, 'hex') : undefined,
		amountMsat: strToBigint(s.amountMsat),
		...(s.sentMsat !== undefined ? { sentMsat: strToBigint(s.sentMsat) } : {}),
		...(s.receivedMsat !== undefined
			? { receivedMsat: strToBigint(s.receivedMsat) }
			: {}),
		...(s.auxiliary === true ? { auxiliary: true as const } : {}),
		...(s.auxiliaryValueMsat !== undefined
			? { auxiliaryValueMsat: strToBigint(s.auxiliaryValueMsat) }
			: {}),
		status: s.status as PaymentStatus,
		direction: s.direction as PaymentDirection,
		route: s.route ? JSON.parse(s.route, reviver) : undefined,
		sharedSecrets: s.sharedSecrets?.map((h) => Buffer.from(h, 'hex')),
		failureCode: s.failureCode,
		failureSourceIndex: s.failureSourceIndex,
		failureReason: s.failureReason,
		createdAt: s.createdAt,
		completedAt: s.completedAt,
		settledHtlcs: s.settledHtlcs,
		metadata: s.metadata
	};
}

// ─── IChainMonitorState ───

export function serializeChainMonitorState(s: IChainMonitorState): string {
	return JSON.stringify(s, (_, v) => {
		if (typeof v === 'bigint') return `__bigint__${v.toString()}`;
		// JSON.stringify invokes Buffer.prototype.toJSON BEFORE the replacer, so
		// Buffers arrive here already converted to { type: 'Buffer', data: [...] }.
		if (isBufferJson(v))
			return `__buffer__${Buffer.from(v.data).toString('hex')}`;
		if (Buffer.isBuffer(v)) return `__buffer__${v.toString('hex')}`;
		return v;
	});
}

/** The { type: 'Buffer', data: number[] } shape Buffer.prototype.toJSON produces. */
function isBufferJson(v: unknown): v is { type: 'Buffer'; data: number[] } {
	return (
		v !== null &&
		typeof v === 'object' &&
		(v as { type?: unknown }).type === 'Buffer' &&
		Array.isArray((v as { data?: unknown }).data)
	);
}

export function deserializeChainMonitorState(json: string): IChainMonitorState {
	return JSON.parse(json, (_, v) => {
		if (typeof v === 'string' && v.startsWith('__bigint__'))
			return BigInt(v.slice(10));
		if (typeof v === 'string' && v.startsWith('__buffer__'))
			return Buffer.from(v.slice(10), 'hex');
		// Legacy rows: Buffers were persisted in raw toJSON form because the old
		// replacer's Buffer.isBuffer check never matched (toJSON ran first).
		if (isBufferJson(v)) return Buffer.from(v.data);
		return v;
	}) as IChainMonitorState;
}

// ─── Gossip types ───

function serializeBufferFields(
	obj: Record<string, unknown>
): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const [key, val] of Object.entries(obj)) {
		if (Buffer.isBuffer(val)) {
			result[key] = `__buffer__${val.toString('hex')}`;
		} else if (typeof val === 'bigint') {
			result[key] = `__bigint__${val.toString()}`;
		} else if (val && typeof val === 'object' && !Array.isArray(val)) {
			result[key] = serializeBufferFields(val as Record<string, unknown>);
		} else if (Array.isArray(val)) {
			result[key] = val.map((item) =>
				item &&
				typeof item === 'object' &&
				!Array.isArray(item) &&
				!Buffer.isBuffer(item)
					? serializeBufferFields(item as Record<string, unknown>)
					: Buffer.isBuffer(item)
					? `__buffer__${item.toString('hex')}`
					: typeof item === 'bigint'
					? `__bigint__${item.toString()}`
					: item
			);
		} else {
			result[key] = val;
		}
	}
	return result;
}

function genericReviver(_: string, v: unknown): unknown {
	if (typeof v === 'string' && v.startsWith('__bigint__'))
		return BigInt(v.slice(10));
	if (typeof v === 'string' && v.startsWith('__buffer__'))
		return Buffer.from(v.slice(10), 'hex');
	return v;
}

export function serializeGraphChannel(ch: IGraphChannel): string {
	const obj = serializeBufferFields(ch as unknown as Record<string, unknown>);
	return JSON.stringify(obj);
}

export function deserializeGraphChannel(json: string): IGraphChannel {
	// Provenance flags round-trip as-is; rows that predate them come back with
	// the flags absent and are resolved by signature verification at the
	// common restore boundary (NetworkGraph.restoreChannel). Absence must NOT
	// be trusted here: pre-#340 rows could hold zero-signature RGS messages
	// persisted alongside a verified update.
	return JSON.parse(json, genericReviver) as IGraphChannel;
}

export function serializeGraphNode(node: IGraphNode): string {
	const obj: Record<string, unknown> = {
		nodeId: `__buffer__${node.nodeId.toString('hex')}`,
		channels: [...node.channels]
	};
	if (node.announcement) {
		obj.announcement = serializeBufferFields(
			node.announcement as unknown as Record<string, unknown>
		);
	}
	if (node.announcementVerified !== undefined) {
		obj.announcementVerified = node.announcementVerified;
	}
	if (node.announcementVerifyDeferred !== undefined) {
		obj.announcementVerifyDeferred = node.announcementVerifyDeferred;
	}
	return JSON.stringify(obj);
}

export function deserializeGraphNode(json: string): IGraphNode {
	const parsed = JSON.parse(json, genericReviver);
	// Provenance resolution for legacy rows happens in NetworkGraph.restoreNode.
	return {
		...parsed,
		channels: new Set(parsed.channels as string[])
	} as IGraphNode;
}

/** The JSON-safe form of an IInvoiceInfo: amountMsat as a decimal string. */
export interface ISerializedInvoiceInfo {
	paymentHash: string;
	bolt11: string;
	amountMsat?: string;
	description?: string;
	expiry: number;
	createdAt: number;
	hold?: boolean;
	bolt12?: boolean;
	cancelledAt?: number;
	jitFee?: { flatFeeSat: number; feePpm: number };
	minFinalCltvExpiry?: number;
	paymentMetadata?: string;
	/** Paid by asset HTLCs; present only then. */
	auxiliary?: true;
}

export function serializeInvoiceInfo(
	invoice: IInvoiceInfo
): ISerializedInvoiceInfo {
	return {
		paymentHash: invoice.paymentHash,
		bolt11: invoice.bolt11,
		amountMsat:
			invoice.amountMsat !== undefined
				? invoice.amountMsat.toString()
				: undefined,
		description: invoice.description,
		expiry: invoice.expiry,
		createdAt: invoice.createdAt,
		hold: invoice.hold,
		bolt12: invoice.bolt12,
		cancelledAt: invoice.cancelledAt,
		jitFee: invoice.jitFee,
		minFinalCltvExpiry: invoice.minFinalCltvExpiry,
		paymentMetadata: invoice.paymentMetadata,
		...(invoice.auxiliary === true ? { auxiliary: true as const } : {})
	};
}

export function deserializeInvoiceInfo(
	s: ISerializedInvoiceInfo
): IInvoiceInfo {
	return {
		paymentHash: s.paymentHash,
		bolt11: s.bolt11,
		amountMsat: s.amountMsat !== undefined ? BigInt(s.amountMsat) : undefined,
		description: s.description,
		expiry: s.expiry,
		createdAt: s.createdAt,
		hold: s.hold,
		bolt12: s.bolt12,
		cancelledAt: s.cancelledAt,
		// A row written before #595 has none; the allowance is then absent
		// and the final hop enforces BOLT 4 unchanged.
		jitFee: s.jitFee,
		// A row written before #770 has none: the final hop then enforces
		// the node default, which is what it advertised.
		minFinalCltvExpiry: s.minFinalCltvExpiry,
		paymentMetadata: s.paymentMetadata,
		...(s.auxiliary === true ? { auxiliary: true as const } : {})
	};
}
