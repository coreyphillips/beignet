/**
 * Serialization helpers for Lightning state persistence.
 *
 * Converts complex types (Buffer, bigint, Maps, ShaChainStore, etc.)
 * to/from JSON-safe representations for SQLite storage.
 */

import { IChannelState, ISpliceInFlight } from '../channel/channel-state';
import { ShaChainStore, IShaChainEntry } from '../keys/shachain';
import { IChannelBasepoints } from '../keys/derivation';
import {
	ChannelState,
	ChannelRole,
	IChannelConfig,
	IHtlcEntry,
	IHtlcSnapshotEntry,
	HtlcDirection,
	HtlcState,
	DEFAULT_CHANNEL_CONFIG
} from '../channel/types';
import { IPaymentInfo, PaymentStatus, PaymentDirection } from '../node/types';
import { IChainMonitorState } from '../chain/chain-monitor';
import { IGraphChannel, IGraphNode } from '../gossip/types';

// ─── Primitive helpers ───

export function bufToHex(buf: Buffer | null | undefined): string | null {
	return buf ? buf.toString('hex') : null;
}

export function hexToBuf(hex: string | null | undefined): Buffer | null {
	return hex ? Buffer.from(hex, 'hex') : null;
}

export function bigintToStr(val: bigint): string {
	return val.toString();
}

export function strToBigint(val: string): bigint {
	return BigInt(val);
}

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

export interface ISerializedHtlcEntry {
	key: string;
	id: string;
	amountMsat: string;
	paymentHash: string;
	cltvExpiry: number;
	onionRoutingPacket: string;
	direction: string;
	state: string;
	/** Route blinding: blinding_point (hex) so an in-flight blinded receive
	 * survives restart and can still peel its onion with the blinded key. */
	blindingPoint?: string;
}

export interface ISerializedHtlcSnapshot {
	commitmentNumber: string;
	htlcs: Array<{
		paymentHash: string;
		amountMsat: string;
		cltvExpiry: number;
		direction: string;
	}>;
}

export function serializeHtlcEntry(
	key: string,
	e: IHtlcEntry
): ISerializedHtlcEntry {
	return {
		key,
		id: bigintToStr(e.id),
		amountMsat: bigintToStr(e.amountMsat),
		paymentHash: e.paymentHash.toString('hex'),
		cltvExpiry: e.cltvExpiry,
		onionRoutingPacket: e.onionRoutingPacket.toString('hex'),
		direction: e.direction,
		state: e.state,
		...(e.blindingPoint
			? { blindingPoint: e.blindingPoint.toString('hex') }
			: {})
	};
}

export function deserializeHtlcEntry(s: ISerializedHtlcEntry): {
	key: string;
	entry: IHtlcEntry;
} {
	return {
		key: s.key,
		entry: {
			id: strToBigint(s.id),
			amountMsat: strToBigint(s.amountMsat),
			paymentHash: Buffer.from(s.paymentHash, 'hex'),
			cltvExpiry: s.cltvExpiry,
			onionRoutingPacket: Buffer.from(s.onionRoutingPacket, 'hex'),
			direction: s.direction as HtlcDirection,
			state: s.state as HtlcState,
			...(s.blindingPoint
				? { blindingPoint: Buffer.from(s.blindingPoint, 'hex') }
				: {})
		}
	};
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
	fundingOutputIndex: number;
	minimumDepth: number;
	localConfig: ISerializedChannelConfig;
	localBasepoints: ISerializedBasepoints;
	localPerCommitmentSeed: string;
	remoteConfig: ISerializedChannelConfig;
	remoteBasepoints: ISerializedBasepoints | null;
	localCommitmentNumber: string;
	remoteCommitmentNumber: string;
	needsCommitment?: boolean;
	/**
	 * A staged (uncommitted) update_fee rate. Persisted so a restart mid
	 * fee-round restores the exact rate the in-flight commitment was built
	 * with. Optional for backward compatibility.
	 */
	pendingFeeratePerKw?: number;
	/**
	 * The feerate baked into the current signed local commitment (the rate
	 * remoteCommitmentSignature covers) — force-close rebuilds at this rate.
	 * Optional for backward compatibility.
	 */
	lastSignedCommitFeeratePerKw?: number;
	localBalanceMsat: string;
	remoteBalanceMsat: string;
	shaChainData: { entries: ISerializedShaChainEntry[]; knownCount: string };
	remoteCurrentPerCommitmentPoint: string | null;
	remoteNextPerCommitmentPoint: string | null;
	localHtlcCounter: string;
	htlcs: ISerializedHtlcEntry[];
	/** Per-remote-commitment HTLC snapshots for penalty completeness (H2). */
	revokedHtlcSnapshots?: ISerializedHtlcSnapshot[];
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
	localShutdownScript: string | null;
	remoteShutdownScript: string | null;
	lastSentCommitmentSigned: string | null;
	lastSentPartialSignatureWithNonce: string | null;
	lastSentHtlcSignatures: string[];
	lastSentRevokeSecret: string | null;
	lastSentRevokeNextPoint: string | null;
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
	fundingVersion?: number;
	commitmentFeeratePerkw?: number;
	fundingLocktime?: number;
	// Liquidity ads (bLIP-0051): if we are the lessor, our to_local (and its
	// exact on-chain script) is CLTV-locked until leaseExpiry. These MUST persist —
	// otherwise a restart rebuilds the commitment without the lock, the peer's cached
	// signature no longer validates, and our whole balance becomes unbroadcastable.
	isLessor?: boolean;
	leaseExpiry?: number;
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
	ourWalletWitnesses: string[][];
	ourWalletInputIndices: number[];
	remoteCommitmentSig: string | null;
	sentTxSignatures: boolean;
	receivedTxSignatures: boolean;
	localSpliceLocked: boolean;
	remoteSpliceLocked: boolean;
	confirmed: boolean;
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
		ourWalletWitnesses: f.ourWalletWitnesses.map((w) =>
			w.map((b) => b.toString('hex'))
		),
		ourWalletInputIndices: [...f.ourWalletInputIndices],
		remoteCommitmentSig: bufToHex(f.remoteCommitmentSig),
		sentTxSignatures: f.sentTxSignatures,
		receivedTxSignatures: f.receivedTxSignatures,
		localSpliceLocked: f.localSpliceLocked,
		remoteSpliceLocked: f.remoteSpliceLocked,
		confirmed: f.confirmed
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
		ourWalletWitnesses: s.ourWalletWitnesses.map((w) =>
			w.map((h) => Buffer.from(h, 'hex'))
		),
		ourWalletInputIndices: [...s.ourWalletInputIndices],
		remoteCommitmentSig: hexToBuf(s.remoteCommitmentSig),
		sentTxSignatures: s.sentTxSignatures,
		receivedTxSignatures: s.receivedTxSignatures,
		localSpliceLocked: s.localSpliceLocked,
		remoteSpliceLocked: s.remoteSpliceLocked,
		confirmed: s.confirmed
	};
}

export function serializeChannelState(
	s: IChannelState
): ISerializedChannelState {
	const htlcs: ISerializedHtlcEntry[] = [];
	for (const [key, entry] of s.htlcs) {
		htlcs.push(serializeHtlcEntry(key, entry));
	}

	let revokedHtlcSnapshots: ISerializedHtlcSnapshot[] | undefined;
	if (s.revokedHtlcSnapshots && s.revokedHtlcSnapshots.size > 0) {
		revokedHtlcSnapshots = [];
		for (const [commitmentNumber, entries] of s.revokedHtlcSnapshots) {
			revokedHtlcSnapshots.push({
				commitmentNumber,
				htlcs: entries.map((e) => ({
					paymentHash: e.paymentHash.toString('hex'),
					amountMsat: bigintToStr(e.amountMsat),
					cltvExpiry: e.cltvExpiry,
					direction: e.direction
				}))
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
		needsCommitment: s.needsCommitment,
		pendingFeeratePerKw: s.pendingFeeratePerKw,
		lastSignedCommitFeeratePerKw: s.lastSignedCommitFeeratePerKw,
		localBalanceMsat: bigintToStr(s.localBalanceMsat),
		remoteBalanceMsat: bigintToStr(s.remoteBalanceMsat),
		shaChainData: serializeShaChainEntries(s.shaChainStore),
		remoteCurrentPerCommitmentPoint: bufToHex(
			s.remoteCurrentPerCommitmentPoint
		),
		remoteNextPerCommitmentPoint: bufToHex(s.remoteNextPerCommitmentPoint),
		localHtlcCounter: bigintToStr(s.localHtlcCounter),
		htlcs,
		revokedHtlcSnapshots,
		remoteCommitmentSignature: bufToHex(s.remoteCommitmentSignature),
		remoteHtlcSignatures: s.remoteHtlcSignatures.map((b) => b.toString('hex')),
		remoteSigningNonce: bufToHex(s.remoteSigningNonce ?? null),
		channelType: bufToHex(s.channelType),
		localChannelReady: s.localChannelReady,
		remoteChannelReady: s.remoteChannelReady,
		localShutdownScript: bufToHex(s.localShutdownScript),
		remoteShutdownScript: bufToHex(s.remoteShutdownScript),
		lastSentCommitmentSigned: bufToHex(s.lastSentCommitmentSigned),
		lastSentPartialSignatureWithNonce: bufToHex(
			s.lastSentPartialSignatureWithNonce
		),
		lastSentHtlcSignatures: s.lastSentHtlcSignatures.map((b) =>
			b.toString('hex')
		),
		lastSentRevokeSecret: bufToHex(s.lastSentRevokeSecret),
		lastSentRevokeNextPoint: bufToHex(s.lastSentRevokeNextPoint),
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
		fundingVersion: s.fundingVersion,
		commitmentFeeratePerkw: s.commitmentFeeratePerkw,
		fundingLocktime: s.fundingLocktime,
		isLessor: s.isLessor,
		leaseExpiry: s.leaseExpiry
	};
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
	if (s.revokedHtlcSnapshots && s.revokedHtlcSnapshots.length > 0) {
		revokedHtlcSnapshots = new Map();
		for (const snap of s.revokedHtlcSnapshots) {
			revokedHtlcSnapshots.set(
				snap.commitmentNumber,
				snap.htlcs.map((e) => ({
					paymentHash: Buffer.from(e.paymentHash, 'hex'),
					amountMsat: strToBigint(e.amountMsat),
					cltvExpiry: e.cltvExpiry,
					direction: e.direction as HtlcDirection
				}))
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
		needsCommitment: s.needsCommitment ?? false,
		pendingFeeratePerKw: s.pendingFeeratePerKw,
		lastSignedCommitFeeratePerKw: s.lastSignedCommitFeeratePerKw,
		localBalanceMsat: strToBigint(s.localBalanceMsat),
		remoteBalanceMsat: strToBigint(s.remoteBalanceMsat),
		shaChainStore: deserializeShaChainStore(s.shaChainData),
		remoteCurrentPerCommitmentPoint: hexToBuf(
			s.remoteCurrentPerCommitmentPoint
		),
		remoteNextPerCommitmentPoint: hexToBuf(s.remoteNextPerCommitmentPoint),
		localHtlcCounter: strToBigint(s.localHtlcCounter),
		htlcs,
		revokedHtlcSnapshots,
		remoteCommitmentSignature: hexToBuf(s.remoteCommitmentSignature),
		remoteHtlcSignatures: s.remoteHtlcSignatures.map((h) =>
			Buffer.from(h, 'hex')
		),
		remoteSigningNonce: hexToBuf(s.remoteSigningNonce) ?? undefined,
		channelType: hexToBuf(s.channelType),
		localChannelReady: s.localChannelReady,
		remoteChannelReady: s.remoteChannelReady,
		localShutdownScript: hexToBuf(s.localShutdownScript),
		remoteShutdownScript: hexToBuf(s.remoteShutdownScript),
		lastSentCommitmentSigned: hexToBuf(s.lastSentCommitmentSigned),
		lastSentPartialSignatureWithNonce: hexToBuf(
			s.lastSentPartialSignatureWithNonce
		),
		lastSentHtlcSignatures: (s.lastSentHtlcSignatures || []).map((h) =>
			Buffer.from(h, 'hex')
		),
		lastSentRevokeSecret: hexToBuf(s.lastSentRevokeSecret),
		lastSentRevokeNextPoint: hexToBuf(s.lastSentRevokeNextPoint),
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
		fundingVersion: (s.fundingVersion ?? 1) as 1 | 2,
		dualFundingSession: null,
		commitmentFeeratePerkw: s.commitmentFeeratePerkw ?? 0,
		fundingLocktime: s.fundingLocktime ?? 0,
		isLessor: s.isLessor,
		leaseExpiry: s.leaseExpiry
	};
}

// ─── IPaymentInfo ───

export interface ISerializedPaymentInfo {
	paymentHash: string;
	preimage?: string;
	amountMsat: string;
	status: string;
	direction: string;
	route?: string; // JSON string
	sharedSecrets?: string[]; // hex
	failureCode?: number;
	failureSourceIndex?: number;
	createdAt: number;
	completedAt?: number;
	metadata?: Record<string, string>;
}

export function serializePaymentInfo(p: IPaymentInfo): ISerializedPaymentInfo {
	return {
		paymentHash: p.paymentHash.toString('hex'),
		preimage: bufToHex(p.preimage) ?? undefined,
		amountMsat: bigintToStr(p.amountMsat),
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
		createdAt: p.createdAt,
		completedAt: p.completedAt,
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
		paymentHash: Buffer.from(s.paymentHash, 'hex'),
		preimage: s.preimage ? Buffer.from(s.preimage, 'hex') : undefined,
		amountMsat: strToBigint(s.amountMsat),
		status: s.status as PaymentStatus,
		direction: s.direction as PaymentDirection,
		route: s.route ? JSON.parse(s.route, reviver) : undefined,
		sharedSecrets: s.sharedSecrets?.map((h) => Buffer.from(h, 'hex')),
		failureCode: s.failureCode,
		failureSourceIndex: s.failureSourceIndex,
		createdAt: s.createdAt,
		completedAt: s.completedAt,
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
	return JSON.stringify(obj);
}

export function deserializeGraphNode(json: string): IGraphNode {
	const parsed = JSON.parse(json, genericReviver);
	return {
		...parsed,
		channels: new Set(parsed.channels as string[])
	} as IGraphNode;
}
