/**
 * BOLT 2: Channel state machine.
 *
 * Transport-agnostic channel lifecycle management. Every method returns
 * ChannelAction[] arrays; the caller (ChannelManager) maps these to
 * actual transport/broadcast operations.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { createFundingScript } from '../script/funding';
import {
	buildTaprootKeySpendWitness,
	createTaprootFundingScript
} from '../script/funding-taproot';
import { encodeShortChannelId } from '../gossip/types';
import {
	encodeAnnouncementSignaturesMessage,
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../gossip/messages';
import { MessageType } from '../message/types';
import {
	encodeOpenChannelMessage,
	IOpenChannelMessage,
	encodeAcceptChannelMessage,
	IAcceptChannelMessage
} from '../message/channel-open';
import {
	encodeFundingCreatedMessage,
	IFundingCreatedMessage,
	encodeFundingSignedMessage,
	IFundingSignedMessage,
	encodeChannelReadyMessage,
	IChannelReadyMessage
} from '../message/channel-funding';
import {
	decodeUpdateAddHtlcMessage,
	encodeUpdateAddHtlcMessage,
	IUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage,
	IUpdateFulfillHtlcMessage,
	encodeUpdateFailHtlcMessage,
	IUpdateFailHtlcMessage,
	encodeUpdateFailMalformedHtlcMessage,
	IUpdateFailMalformedHtlcMessage,
	encodeUpdateFeeMessage,
	IUpdateFeeMessage,
	IUpdateBlockheightMessage
} from '../message/channel-update';
import {
	encodeCommitmentSignedMessage,
	decodeCommitmentSignedMessage,
	ICommitmentSignedMessage,
	encodeRevokeAndAckMessage,
	IRevokeAndAckMessage
} from '../message/channel-commitment';
import {
	encodeShutdownMessage,
	IShutdownMessage,
	encodeClosingSignedMessage,
	IClosingSignedMessage,
	ClosingSigVariant,
	IClosingCompleteMessage,
	IClosingSigMessage,
	encodeClosingCompleteMessage,
	encodeClosingSigMessage
} from '../message/channel-close';
import { isDustOutput, calculateClosingFee } from '../chain/closing';
import {
	encodeChannelReestablishMessage,
	IChannelReestablishMessage
} from '../message/channel-reestablish';
import { canScopeWireError, encodeErrorMessage } from '../message/error';
import {
	ChannelAction,
	ChannelActionType,
	ISendMessageAction,
	IErrorAction
} from './channel-actions';
import {
	ChannelState,
	ChannelRole,
	IChannelConfig,
	IHtlcEntry,
	IHtlcSnapshotEntry,
	HtlcDirection,
	HtlcState,
	BITCOIN_CHAIN_HASH,
	MAX_FUNDING_SATOSHIS,
	DEFAULT_CHANNEL_CONFIG
} from './types';
import {
	IAbandonedLocalAdd,
	IChannelState,
	IRemoteForwardingPolicy,
	ISpliceInFlight,
	IV2InFlight,
	createOpenerState,
	createAcceptorState,
	mustNotBroadcastCommitment,
	RecoveryCloseReason,
	ChannelCloseReason
} from './channel-state';
import { ChannelRecoveryStatus } from '../recovery/channel-status';
import {
	deriveChannelId,
	deriveV2ChannelId,
	deriveV2TemporaryChannelId,
	validateOpenChannelParams,
	validatePeerOpenChannelParams,
	validateAcceptChannelParams,
	validateU64,
	isValidShutdownScript
} from './validation';
import { IChannelBasepoints } from '../keys/derivation';
import { FeatureFlags, Feature } from '../features/flags';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import { ChannelSigner, ISigner } from '../keys/signer';
import {
	buildLocalCommitment,
	aggregateLocalCommitmentSig,
	buildRemoteCommitment,
	signRemoteCommitment,
	verifyRemoteCommitmentSig,
	verifyRemoteCommitmentPartial,
	verifyRemoteHtlcSignatures,
	verifyRemoteHtlcSignaturesTaproot,
	funderCommitmentCostSats,
	getCommitmentFeeRate,
	getLocalCommitmentFeeRate,
	getRemoteCommitmentFeeRate,
	getLocalCommitmentLeaseBlockheight,
	HTLC_SUCCESS_WEIGHT
} from './commitment-builder';
import {
	hasScidAliasChannelType,
	isAnchorChannel,
	isTaprootChannel,
	scidAliasAnnounceRefusal,
	validateV2ChannelType
} from './types';
import { generateNonce } from '../crypto/musig';
import { isValidPublicKey } from '../crypto/ecdh';
import { IStfuMessage, encodeStfuMessage } from '../message/stfu';
import { QuiescenceManager, QuiescenceState } from './quiescence';
import {
	ISpliceMessage,
	ISpliceAckMessage,
	ISpliceLockedMessage,
	IStartBatchMessage,
	encodeSpliceMessage,
	encodeSpliceAckMessage,
	encodeSpliceLockedMessage,
	encodeStartBatchMessage
} from '../message/splice';
import { SpliceSession, SpliceState, ISpliceSessionParams } from './splice';
import {
	estimateSpliceTxWeight,
	spliceFeeSats,
	dualFundingContributionWeight,
	SPLICE_TX_BASE_WEIGHT,
	SHARED_FUNDING_INPUT_WEIGHT,
	outputWeight
} from './splice-weight';
import {
	buildSpliceTx,
	findInputIndex,
	findOutputIndex,
	signSpliceSharedInput,
	verifySpliceSharedInput,
	finalizeSpliceSharedWitness,
	ISpliceTxInput,
	ISpliceTxOutput
} from './splice-tx';
import {
	encodeOpenChannel2Message,
	IOpenChannel2Message,
	encodeAcceptChannel2Message,
	IAcceptChannel2Message
} from '../message/dual-funding';
import {
	DualFundingSession,
	DualFundingState,
	IDualFundingParams,
	rbfFeerateFloor
} from './dual-funding';
import { computeLeaseFeeSat, computeLeaseExpiry } from './liquidity-ads';
import {
	encodeTxCompleteMessage,
	encodeTxSignaturesMessage,
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	encodeTxRemoveInputMessage,
	encodeTxRemoveOutputMessage,
	encodeTxInitRbfMessage,
	encodeTxAckRbfMessage,
	encodeTxAbortMessage,
	ITxAddInputMessage,
	ITxAddOutputMessage,
	ITxRemoveInputMessage,
	ITxRemoveOutputMessage,
	ITxSignaturesMessage,
	ITxInitRbfMessage,
	ITxAckRbfMessage
} from '../message/interactive-tx';
import {
	IInteractiveTxInput,
	IInteractiveTxOutput,
	InteractiveTxState
} from '../interactive-tx/types';
import {
	DUST_LIMIT_SATS,
	validateCompletedInteractiveTx
} from '../interactive-tx/validation';

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
}

function getPerCommitmentSecret(
	seed: Buffer,
	commitmentNumber: bigint
): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	return generateFromSeed(seed, index);
}

function sendMsg(
	messageType: MessageType,
	payload: Buffer
): ISendMessageAction {
	return { type: ChannelActionType.SEND_MESSAGE, messageType, payload };
}

/**
 * A BOLT 2 reconnect retransmission: the same bytes the peer may already
 * hold, replayed rather than newly authorized. Marked so the recovery outbox
 * is not written again for them, while the persist gate still applies.
 */
function replayMsg(
	messageType: MessageType,
	payload: Buffer
): ISendMessageAction {
	return {
		type: ChannelActionType.SEND_MESSAGE,
		messageType,
		payload,
		replay: true
	};
}

/**
 * A recovery declaration (spec 5.6 and 5.8): the wire half of "our state is
 * stale, or unprovable, so close with YOUR commitment".
 *
 * Marked so the quorum barrier holds it until the disposition that authorizes
 * it is durable. What that protects is the never-broadcast invariant itself:
 * if the peer acts on this while the frame carrying `dataLossDetected` or
 * `recoveryCloseReason` is still only local, a restore below that frame comes
 * back believing it may broadcast a commitment the peer has already revoked.
 */
function declMsg(
	messageType: MessageType,
	payload: Buffer
): ISendMessageAction {
	return {
		type: ChannelActionType.SEND_MESSAGE,
		messageType,
		payload,
		durabilityCritical: true
	};
}

/**
 * A refusal that reaches BOTH the peer and the local caller.
 *
 * The pairing, and the order, are the point. A bare ChannelActionType.ERROR is
 * never put on the wire: ChannelManager._dispatchActions only drops the
 * temporary channel and emits a local event, so a refusal made of one deletes
 * our half of a negotiation while the peer stays parked on a message it will
 * never get an answer to (issues 381, 393). The wire action LEADS, because that
 * local action's removeCurrentTempChannel must not forget the channel before
 * its cancellation has been handed to the transport.
 *
 * `channelId` is the SCOPE, and it is the caller's to choose: the id the PEER's
 * side keys this negotiation by, so the wire scope and the local cleanup can
 * never name different entries.
 *
 * `cleanup` says what the dispatcher should do with this channel's
 * registration; see IErrorAction.
 *
 * For a channel that already has a life of its own, _failChannelWithWireError
 * is the heavier shape: it marks ERRORED and persists first. Both route their
 * wire half through wireErrorFor, so the scope rule below is the same one.
 */
function refuseWithWireError(
	channelId: Buffer,
	reason: string,
	cleanup?: IErrorAction['cleanup']
): ChannelAction[] {
	const local: IErrorAction = {
		type: ChannelActionType.ERROR,
		message: reason,
		...(cleanup ? { cleanup } : {})
	};
	const wire = wireErrorFor(channelId, reason);
	return wire ? [wire, local] : [local];
}

/**
 * The wire half of a refusal, or null when this id cannot carry one.
 *
 * Two ids are refused locally instead of answered, for the reason
 * ChannelManager.refuseInboundOpen refuses them. BOLT 1 reserves the all-zero
 * channel_id for "all channels with this peer", so echoing one turns the
 * refusal of a single channel into an instruction to fail every channel we have
 * with the sender. And a length encodeErrorMessage will not accept would THROW,
 * which is worse than silence at either call site: out of a refusal arm it
 * loses the local unwind along with the send, and out of _failChannelWithWireError
 * it escapes after the channel has already been marked ERRORED, so the caller
 * gets no actions at all for a channel that is now failed.
 *
 * Suppressed HERE rather than at each caller because every wire refusal in this
 * file routes through it, and a caller-side check protects only the caller that
 * remembers to make it. The refusal or the failure still stands, just silently:
 * there is no id we could answer under that means what we mean.
 */
function wireErrorFor(
	channelId: Buffer,
	reason: string
): ISendMessageAction | null {
	if (!canScopeWireError(channelId)) {
		return null;
	}
	return sendMsg(
		MessageType.ERROR,
		encodeErrorMessage({
			channelId,
			data: Buffer.from(reason, 'ascii')
		})
	);
}

/**
 * Compute channel reserve: 1% of funding (matching LND/CLN/Eclair),
 * floored at the greater of dust limit and 546 sats (LND's minimum),
 * capped at funding / 5 (20%). The cap is local policy for the reserve we
 * PROPOSE on a v1 open, not a spec rule: BOLT 2 states no maximum. It must
 * not be applied to a v2 channel, whose reserve is not negotiated at all
 * (see v2ReserveWeKeep).
 */
const MIN_CHANNEL_RESERVE_SATOSHIS = 546n; // LND enforces P2PKH dust limit as minimum reserve

/**
 * Stamped on IChannelState.channelReserveVersion by every site that writes the
 * reserve we enforce, so a later load can tell a row that negotiated its value
 * from one that never had a value written at all. See the field's own comment
 * for why this is a version and not a flag, and what bumping it obliges.
 */
const ENFORCED_RESERVE_VERSION = 1;

/**
 * Liquidity ads: how far a buyer-supplied lease blockheight may sit from our
 * current tip before we reject it (S-L/S-W MEDIUM). The buyer sets it to its
 * own tip; a small past tolerance absorbs propagation skew, and the future
 * tolerance (a day of blocks) bounds how long the resulting CLTV can freeze
 * our to_local without being so tight it rejects an honest peer a few blocks
 * ahead.
 */
const LEASE_BLOCKHEIGHT_PAST_TOLERANCE = 6;
const LEASE_BLOCKHEIGHT_FUTURE_TOLERANCE = 144;
function bigIntMax(a: bigint, b: bigint): bigint {
	return a > b ? a : b;
}

function bigIntMin(a: bigint, b: bigint): bigint {
	return a < b ? a : b;
}

function computeChannelReserve(
	fundingSatoshis: bigint,
	dustLimitSatoshis: bigint
): bigint {
	const onePercent = fundingSatoshis / 100n;
	const maxReserve = fundingSatoshis / 5n;
	const minReserve =
		dustLimitSatoshis > MIN_CHANNEL_RESERVE_SATOSHIS
			? dustLimitSatoshis
			: MIN_CHANNEL_RESERVE_SATOSHIS;
	let reserve = onePercent;
	if (reserve < minReserve) reserve = minReserve;
	if (reserve > maxReserve) reserve = maxReserve;
	return reserve;
}

/**
 * The channel reserve of a v2 (dual-funded) channel, which BOLT 2 leaves out of
 * open_channel2/accept_channel2 entirely: "the channel reserve is fixed at 1% of
 * the total channel balance ... rounded down to the nearest whole satoshi or the
 * `dust_limit_satoshis`, whichever is greater." Both peers DERIVE it, so there is
 * nothing to negotiate and, crucially, no maximum: the v1 helper's 20% cap can
 * pull the result BELOW the dust limit on a small channel, which is exactly the
 * case the spec's dust floor exists to prevent (a reserve under dust admits a
 * commitment whose outputs all trim away, leaving no spendable exit).
 *
 * The spec does not say WHOSE dust_limit_satoshis floors it, and the two
 * reference implementations disagree: eclair (Commitments.scala localChannelReserve
 * / remoteChannelReserve) floors each side at the OTHER peer's dust limit, while
 * CLN (openingd/dualopend.c set_reserve) gives both sides one value floored at the
 * OPENER's. So the two sides are derived directionally instead of mirroring either,
 * which is safe against both peers at any dust pairing (and identical to both
 * whenever the two dust limits agree, which is every real pairing):
 *
 *   - the reserve WE keep takes the maximum, so it is never below either peer's
 *     dust limit and never below what a conforming peer requires of us. Being
 *     generous here only costs us spendable balance; the reserve is not on the
 *     wire and the commitment builder never reads it, so it cannot change
 *     commitment bytes. This is also the only variant that keeps our reserve
 *     output non-dust in BOTH commitments (BOLT 2's rationale for the v1 dust
 *     couplings is that each reserve sits above both dust limits).
 *   - the reserve we ENFORCE on the peer takes the minimum dust limit and skips
 *     beignet's stricter 546-sat policy floor, so it can never exceed what eclair
 *     (max(1%, our dust)) or CLN (max(1%, opener dust)) computes for itself in
 *     either role. A local policy applied here would reject an honest peer's
 *     spec-legal HTLC.
 *
 * Under-enforcing is inert as far as the peer's own gate is concerned, but NOT
 * as far as our own commitment is concerned: once the two dust limits differ,
 * this value sits below the limit OUR commitment trims at, so a peer balance
 * that clears it can still be dust to us. Channel._localCommitmentEmptyRefusal
 * is what keeps that from emptying the commitment we hold (issue #386).
 */
function v2ReserveWeKeep(
	fundingSatoshis: bigint,
	ourDustLimitSatoshis: bigint,
	peerDustLimitSatoshis: bigint
): bigint {
	return bigIntMax(
		bigIntMax(fundingSatoshis / 100n, MIN_CHANNEL_RESERVE_SATOSHIS),
		bigIntMax(ourDustLimitSatoshis, peerDustLimitSatoshis)
	);
}

function v2ReserveWeEnforce(
	fundingSatoshis: bigint,
	ourDustLimitSatoshis: bigint,
	peerDustLimitSatoshis: bigint
): bigint {
	return bigIntMax(
		fundingSatoshis / 100n,
		bigIntMin(ourDustLimitSatoshis, peerDustLimitSatoshis)
	);
}

/**
 * The reserve we may enforce on the peer at a given capacity, re-derived from a
 * row alone.
 *
 * The two callers (splice adoption and the load-time repair) both revisit the
 * enforced reserve of a channel that is already open, where the value we
 * advertised is either gone (a row written before issue #381 recorded it) or no
 * longer priced at the current capacity (a splice). Neither may land ABOVE what
 * the peer keeps for itself: over-enforcement refuses an HTLC the peer believes
 * is legal, the refusal is a bare ERROR action the peer never sees, and its next
 * commitment_signed then covers an HTLC we do not hold. Erring low is inert,
 * since the peer's own gate binds and no commitment builder reads this value.
 *
 * Which of the two rules the peer is applying is decided by the row, not by a
 * guess:
 *
 * - DERIVED, for a v2 row or any row that has ever been spliced. A v2 reserve
 *   was never negotiated, so both sides derive it. And eclair switches a channel
 *   to the derived rule for `DualFunding || fundingTxIndex > 0`
 *   (Commitments.scala localChannelReserve), i.e. once it has been spliced, v1
 *   included, keeping max(1% of capacity, a dust limit).
 *   v2ReserveWeEnforce is at or below that in either role and at either peer's
 *   dust pairing, which is exactly why it omits beignet's 546-sat policy floor:
 *   that floor sits above what a spliced peer keeps on a small capacity.
 *   spliceFundingTxid is the marker because it is persisted, starts null and is
 *   only ever assigned; fundingTxIndex is NOT a splice counter (adoption resets
 *   it to 0).
 * - NEGOTIATED, for an unspliced v1 row: the peer keeps the constant we
 *   advertised at open, which is computeChannelReserve at this capacity.
 *
 * The unspliced v1 branch deliberately omits the acceptor's peer-dust floor,
 * which is why it reproduces the OPENER's advertisement exactly and an
 * ACCEPTOR's only from below. That floor arrived in PR #115 and our own dust
 * floor in #381, while computeChannelReserve itself has not changed since the
 * first commit, so a row written before either advertised the unfloored value
 * and nothing on disk tells the two apart. Re-deriving today's floors would put
 * those rows above what their peer keeps, which is the failure this exists to
 * prevent; omitting them can only under-enforce. The unfloored result is still a
 * sound lower bound in both roles, since an acceptor's advertisement is a max
 * over it and an opener's open is refused outright when it lands under our own
 * dust limit (validateOpenChannelParams).
 *
 * A backup-recovered row hardcodes fundingVersion 1 even for a v2 channel, so it
 * takes the negotiated branch; that errs low, and such a row is ERRORED with
 * dataLossDetected and never admits an HTLC anyway.
 */
function reserveWeEnforceAt(
	state: IChannelState,
	capacitySatoshis: bigint
): bigint {
	const ourDust = state.localConfig.dustLimitSatoshis;
	if (state.fundingVersion === 2 || state.spliceFundingTxid) {
		return v2ReserveWeEnforce(
			capacitySatoshis,
			ourDust,
			state.remoteConfig.dustLimitSatoshis
		);
	}
	return computeChannelReserve(capacitySatoshis, ourDust);
}

/**
 * Compute a transaction id (internal byte order, as bitcoinjs addInput expects)
 * from a serialized previous transaction. Used to resolve the prevout txid of an
 * interactive-tx input that arrived with the full prevtx.
 */
function extractTxidFromPrevTx(prevTx: Buffer): Buffer {
	return Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash());
}

/**
 * Best-effort value (sats) of the output a peer's interactive-tx input spends,
 * read from its prev_tx bytes. Returns null when prev_tx is absent or
 * unparseable (strict prev_tx enforcement is tracked separately, S-2.H3).
 */
function interactiveInputValueSats(input: IInteractiveTxInput): bigint | null {
	if (!input.prevTx || input.prevTx.length === 0) return null;
	try {
		const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
		const vout = input.prevTxVout ?? input.prevOutputIndex;
		if (vout < 0 || vout >= prev.outs.length) return null;
		return BigInt(prev.outs[vout].value);
	} catch {
		return null;
	}
}

/**
 * Lower-bound signed weight (WU) of a non-shared interactive-tx input, for
 * the fee-sufficiency audit. The audit's minimum fee must never exceed what
 * an honest signer actually pays: bitcoind-backed peers (eclair, CLN) grind
 * low-R signatures, so a P2WPKH witness is 107 WU (71 byte sig), not the
 * 108 our own funding-side estimate reserves, and a P2TR key-spend witness
 * is 66 WU (64 byte Schnorr sig, default sighash). Charging the funding
 * estimate here refused every solo-funded eclair v2 open paying the exact
 * negotiated feerate (issue #359). Unknown or unparseable prevouts fall
 * back to the P2WPKH floor.
 */
function auditMinInputWeightWu(input: IInteractiveTxInput): number {
	// outpoint(36) + scriptSig len(1) + sequence(4) = 41 bytes x4
	const base = 164;
	try {
		if (input.prevTx && input.prevTx.length >= 32) {
			const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
			const out = prev.outs[input.prevTxVout ?? input.prevOutputIndex];
			if (
				out &&
				out.script.length === 34 &&
				out.script[0] === 0x51 &&
				out.script[1] === 0x20
			) {
				// P2TR key-spend: count(1) + Schnorr sig(1+64)
				return base + 66;
			}
		}
	} catch {
		/* fall through to the P2WPKH floor */
	}
	// P2WPKH: count(1) + low-R DER sig(1+71) + pubkey(1+33)
	return base + 107;
}

/** A force close this channel cannot perform, and why. */
export interface IForceClosePlanRefused {
	ok: false;
	error: string;
}

/**
 * A force close that is going to work: everything fallible is already done,
 * and the live channel has not been touched.
 */
export interface IForceClosePlanReady {
	ok: true;
	/** The fully witnessed commitment, built against the planned view. */
	commitmentTx: Buffer;
	/**
	 * The state a CONFIRMED splice contributes to that view, or null when
	 * there is no splice to adopt. Applied as one assignment, so the channel
	 * either has the whole spliced view or none of it.
	 */
	spliceAdoption: Partial<IChannelState> | null;
	/**
	 * The state a CONFIRMED superseded v2 RBF attempt contributes to that
	 * view, or null when there is none to adopt. Applied as one assignment,
	 * like the splice adoption above.
	 */
	v2Adoption: Partial<IChannelState> | null;
	/**
	 * The taproot verification nonce the commitment was aggregated under.
	 *
	 * The EXACT object generateNonce returned, never a copy: the MuSig2
	 * library finds the secret nonce by the public nonce it was registered
	 * with, so a duplicated buffer signs nothing.
	 */
	localNonce: Uint8Array | null;
	/** The id the CHANNEL_CLOSED action carries. */
	channelId: Buffer;
}

export type ForceClosePlan = IForceClosePlanRefused | IForceClosePlanReady;

/**
 * A wallet-owned input contributed to a splice-in. The wallet provides the full
 * previous transaction (so the peer can build the identical tx) and a closure
 * that signs this input on the assembled splice transaction, returning its
 * witness stack. This keeps wallet private keys out of the channel.
 */
export interface ISpliceWalletInput {
	/** Serialized previous transaction containing the output being spent. */
	prevTx: Buffer;
	/** Index of the output being spent in prevTx. */
	prevOutputIndex: number;
	/** Value of the output being spent, in satoshis. */
	value: bigint;
	/** nSequence for this input. */
	sequence: number;
	/** Produce the witness stack for this input on the given (unsigned) tx.
	 *  P2TR inputs need every input's prevout script and value for the
	 *  BIP 341 sighash; callers supply them via `prevouts` (aligned with
	 *  tx.ins). P2WPKH signers ignore the argument. */
	signWitness: (
		tx: import('bitcoinjs-lib').Transaction,
		inputIndex: number,
		value: bigint,
		prevouts?: { scripts: Buffer[]; values: bigint[] }
	) => Buffer[];
	/**
	 * Whether the spent output is confirmed. Used to honor the peer's
	 * require_confirmed_inputs; treated as unknown when omitted.
	 */
	confirmed?: boolean;
}

/**
 * Taproot cooperative close: the manager's cached MuSig2 signing session for
 * the closing tx at a specific fee. Opaque to the channel state machine (the
 * session and tx types belong to the manager's crypto layer); the channel
 * only owns its lifecycle, clearing it whenever the closing nonces refresh.
 */
export interface ITaprootClosingCache {
	feeSatoshis: bigint;
	session: unknown;
	tx: import('bitcoinjs-lib').Transaction;
	/** Our 32-byte MuSig2 partial signature over the closing tx, once made. */
	ourPartialSig: Buffer | null;
}

/**
 * Lightning channel state machine.
 */
export class Channel {
	private _state: IChannelState;
	private _signer: ISigner | null = null;
	private _quiescence: QuiescenceManager = new QuiescenceManager();
	/**
	 * A peer-initiated stfu arrived while updates were pending (issue 431).
	 * The RECEIVED_STFU transition already happened; the reply is owed and
	 * goes out from _maybeAnswerOwedStfu once the drain completes. In-memory
	 * only: quiescence never survives a disconnect.
	 */
	private _stfuReplyOwed = false;
	private _spliceSession: SpliceSession | null = null;
	// A splice the caller requested while the channel was not yet quiescent.
	// Fired automatically once we reach QUIESCENT (we drive quiescence ourselves
	// so we become the quiescence initiator, as splice requires). A request the
	// operator cancelled while our stfu was still unanswered stays parked with
	// cancelled=true: quiescence has no un-stfu, so once the handshake completes
	// the deferred hook must still open the splice conversation and immediately
	// tx_abort it, or both sides would sit HTLC-frozen until a disconnect
	// (issue #370). That unwind is owed only for a handshake the splice
	// machinery opened (ownsQuiescence): a quiescence the operator started
	// with initiateQuiescence() outlives a cancelled splice that merely
	// joined it. When the funder peer initiates quiescence concurrently and
	// wins the BOLT 2 tie-break (issue #372), the request is dropped instead
	// (with a surfaced error unless cancelled): the session belongs to the
	// peer and a non-initiator must not send splice_init. Memory-only:
	// quiescence never survives a disconnect.
	private _pendingSplice: {
		relativeSatoshis: bigint;
		fundingFeeratePerkw: number;
		locktime: number;
		cancelled: boolean;
		ownsQuiescence: boolean;
	} | null = null;
	// Splice interactive-tx driving (initiator side). The ordered contributions
	// we still need to send (shared input, new funding output, splice-out
	// destination, etc.), a cursor into them, and whether we have already sent
	// our tx_complete. Computed when we enter TX_NEGOTIATION.
	private _spliceContributions: Array<
		| { kind: 'input'; input: IInteractiveTxInput; sharedInputTxid?: Buffer }
		| { kind: 'output'; output: IInteractiveTxOutput }
	> | null = null;
	private _spliceContribIndex = 0;
	private _spliceSentTxComplete = false;
	private _spliceSentTxSigs = false;
	// Mid-splice commitment round (BOLT 2 splicing). After tx_complete, both peers
	// exchange commitment_signed for the NEW commitment spending the spliced
	// funding output (no revoke_and_ack — both old and new commitments stay valid
	// until splice_locked), THEN exchange tx_signatures. We track whether we have
	// sent/received our splice commitment_signed and cache the peer's signature on
	// our new commitment (adopted as remoteCommitmentSignature at completeSplice).
	private _spliceSentCommitment = false;
	private _spliceReceivedCommitment = false;
	// BOLT 2 v2 establishment: after both tx_completes the peers exchange
	// commitment_signed for commitment #0 of the new funding output, and only
	// then tx_signatures (lower-total-input-sats side first). Process-local
	// mirrors of the durable v2InFlight record: once our commitment_signed
	// leaves, the open must survive disconnect AND restart (BOLT 2 requires
	// the exchange to resume over channel_reestablish.next_funding), and
	// restoreV2InFlight rebuilds these flags from the record.
	private _v2SentCommitment = false;
	private _v2ReceivedCommitment = false;
	/**
	 * BOLT 2 interactive-tx tx_signatures ordering tie-break: whether OUR
	 * node_id sorts (lexicographically) below the peer's. Set by the
	 * ChannelManager (the channel itself never learns node ids); null until
	 * known, in which case ordering falls back to the non-initiator.
	 */
	private _localNodeIdLower: boolean | null = null;

	setLocalNodeIdLower(lower: boolean): void {
		this._localNodeIdLower = lower;
	}
	/** Witnesses provided by the caller before the ordering allowed sending. */
	private _v2PendingTxSigs: {
		txid: Buffer;
		outputIndex: number;
		witnesses: Buffer[][];
	} | null = null;
	private _spliceRemoteCommitmentSig: Buffer | null = null;
	// Peer's second-level HTLC sigs paired with _spliceRemoteCommitmentSig:
	// committed HTLCs riding through the splice (S-2.M8) put HTLC outputs on
	// the spliced commitment, and a force-close on the new funding needs
	// these to claim them.
	private _spliceRemoteHtlcSigs: Buffer[] | null = null;
	// start_batch collection: while a fully-signed splice awaits confirmation,
	// every commitment update arrives as a batch of commitment_signed messages
	// (one per active funding output) announced by start_batch and answered by
	// a single revoke_and_ack. In-memory only: a disconnect mid-batch simply
	// re-batches on retransmission.
	private _pendingBatch: {
		size: number;
		msgs: ICommitmentSignedMessage[];
	} | null = null;
	// Wire bytes of the last commitment batch WE sent during the pending-lock
	// window, retained for verbatim retransmission on reestablish until the
	// peer's revoke_and_ack acknowledges it. Not part of channel state: a
	// restart repopulates it from the recovery outbox via restoreLastSentBatch,
	// which is the only source of the exact bytes for a taproot channel (the
	// rebuild fallback below deliberately refuses to re-sign one).
	private _lastSentBatch: {
		startBatch: Buffer;
		commitments: Buffer[];
	} | null = null;
	// Outcome of the last processed channel_reestablish this SESSION (recovery
	// 5.6 status machine): 'replay' when we served retransmissions, 'clean'
	// when the counters simply agreed. In-memory only - after a restart the
	// channel is back in AWAITING_REESTABLISH and the status derives from
	// that. Cleared again once fresh signed traffic proves the exchange over.
	private _lastReestablishOutcome: 'replay' | 'clean' | null = null;
	// Watchtower: the remote commitment transactions we have signed, keyed by the
	// per-commitment point they use, so that when the peer later reveals that
	// point's secret (revoke_and_ack) we can ship the exact revoked tx to a tower.
	// In-memory only and bounded; unrevoked states number at most a couple.
	private _remoteCommitmentTxCache = new Map<string, string>();
	private static readonly REVOKED_TX_CACHE_MAX = 8;
	// We dropped an unresumable splice on disconnect/restart, but the peer may
	// still hold its in-flight copy (CLN never forgets one on its own — it blocks
	// the channel waiting for the splice commitment_signed). Triggers a tx_abort
	// ahead of our next channel_reestablish so the peer discards it.
	private _forgottenSplice = false;
	// We sent that tx_abort and expect the peer's tx_abort echo (and, on CLN, a
	// fresh channel_reestablish after its channeld restarts on the same
	// connection). While set, the peer's tx_abort is an ack — not an error — and
	// a remote `error` for this channel is part of the abort dance, not a
	// channel failure.
	/**
	 * BOLT 7 chain scope for the channel_announcement / channel_update this
	 * channel builds AND signs (buildAnnouncementData is both the signing
	 * digest and the emitted message). Set by the ChannelManager from its
	 * configured chain; the previous hardcoded mainnet made every non-mainnet
	 * announcement invalid for the actual chain (S-7.M1).
	 */
	announcementChainHash: Buffer = BITCOIN_CHAIN_HASH;
	private _spliceAbortPending = false;
	/**
	 * We have sent a tx_abort on the current negotiation (proactively, as an
	 * echo, or refusing a peer message). BOLT 2: a node that has itself sent
	 * tx_abort MUST NOT send another in reply to the peer's, so while this is
	 * set, handleTxAbort consumes incoming aborts silently. Without it, two
	 * nodes that have both forgotten the transaction answer each other's
	 * answers forever (issue 294): the ack-latch above is a boolean, so a
	 * second outstanding abort of ours already overflowed it, and each echo
	 * then met a side with no session and no memory of having answered.
	 * Cleared on disconnect and when a fresh interactive negotiation starts.
	 */
	private _txAbortSent = false;
	/**
	 * This channel's record was read off disk at startup, so it says what some
	 * EARLIER process durably wrote and not what that process went on to do. A
	 * Recovery Capsule is best-effort recency by construction (BOLT 1 peer
	 * storage is rate limited and providers need not return the latest blob,
	 * docs/RECOVERY-PROTOCOL.md 5.4), so `sentTxSignatures: false` here can
	 * describe an open whose signatures did leave and whose funding is on
	 * chain. Set by ChannelManager.restoreChannel's startup caller; in memory
	 * because every start re-reads the row and re-sets it (issue #463).
	 */
	private _recordRestoredFromDisk = false;
	// We refused a COMPLETED splice negotiation with tx_abort. The peer sends
	// its mid-splice commitment_signed right after its final tx_complete, so
	// that message can already be in flight when our abort leaves; judged
	// against the post-abort channel it would fail the channel on a signature
	// that was never meant for it. While set, an arriving commitment_signed
	// is CLASSIFIED, not blanket-ignored: a funding_txid-tagged commitment is
	// the aborted splice's stray (swallowed, guard kept armed since a stray
	// batch can have several members), an untagged one is legitimate normal
	// traffic (guard cleared, processed). The guard deliberately survives
	// tx_abort: with reentrant synchronous routing the peer's abort echo can
	// arrive BEFORE the stray it queued behind its tx_complete (issue 350),
	// and with a symmetric audit failure the peer's tx_abort is its OWN
	// refusal with no stray in flight at all, so no arrival order of aborts
	// proves the window over. A live NEW splice session also clears it: the
	// peer only starts one after processing our abort, which is after any
	// stray was emitted, so the stray has been classified by then in every
	// ordering. Cleared on disconnect.
	private _spliceAbortIgnoreCommitment = false;
	// One-shot: we answered a post-reestablish channel_reestablish (a peer whose
	// channel process restarted on the same connection, e.g. CLN after a
	// tx_abort) by retransmitting ours. Without the latch two nodes that both
	// retransmit would ping-pong reestablish forever.
	private _reestablishRetransmitted = false;
	// Splice-out only: where withdrawn funds are paid (wallet-owned script) and
	// how much. Set by the node when it requests a splice-out.
	private _spliceOutDestination: { script: Buffer; sats: bigint } | null = null;
	// Splice-in only: wallet inputs (each with its prevTx and a witness-signing
	// closure) and the change script, provided by the node from its on-chain
	// wallet. The closure lets the wallet sign its own inputs without the channel
	// holding wallet keys.
	private _spliceInInputs: {
		inputs: ISpliceWalletInput[];
		changeScript: Buffer;
	} | null = null;
	// Dual-funding ACCEPTOR contribution (v2 open, e.g. a bLIP-0051 lease we
	// sell): wallet inputs funding our fundingSatoshis share, the change
	// script, and the contribution amount. Same wallet-closure model as
	// _spliceInInputs — the wallet signs its own inputs.
	private _dualFundingContribution: {
		inputs: ISpliceWalletInput[];
		changeScript: Buffer;
		contributionSats: bigint;
		feeratePerKw: number;
	} | null = null;
	// The ordered interactive-tx contributions derived from the above, sent
	// one per turn (interactive-tx alternation) by _driveDualFunding.
	private _dualFundingContribs: Array<
		| { kind: 'input'; input: IInteractiveTxInput }
		| { kind: 'output'; output: IInteractiveTxOutput }
	> | null = null;
	private _dualFundingContribIndex = 0;
	// Set once our v2 tx_signatures witnesses have been provided to the
	// session, so later flushes never re-provide.
	private _v2TxSigsReleased = false;
	// One-shot latch for TX_SIGNATURES_NEEDED: the caller-owed release is
	// signaled once per connection cycle (markForReestablish re-arms it), not
	// on every flush. In-memory only; a restart re-arms it, which is the
	// point (issue 307): the pending witnesses died with the process and the
	// embedder must be told to re-drive sendTxSignatures.
	private _v2CallerTxSigsSignaled = false;
	// Our un-acked tx_init_rbf (feerate/locktime it proposed, and the
	// recorded funding txid it was bound to; the ack revalidates the
	// binding). Connection scoped: BOLT 2 starts the renegotiation only at
	// tx_ack_rbf, so nothing is replaced while this is pending and a
	// disconnect simply forgets it. While set, the recorded attempt's
	// tx_signatures release is frozen (_maybeSendV2TxSigs).
	private _pendingRbfInit: {
		feerate: number;
		locktime: number;
		fundingTxid: Buffer;
		/**
		 * The changed funding_output_contribution this request proposed, and
		 * the wallet inputs selected to fund a raise. Carried here so the ack
		 * applies EXACTLY the split that went out, and so a request that dies
		 * unapplied (refusal, disconnect, failed binding) can hand its
		 * now-orphaned pledges back to the wallet.
		 */
		contribution?: {
			fundingSatoshis: bigint;
			topUpInputs?: ISpliceWalletInput[];
		};
	} | null = null;
	/**
	 * Wallet inputs selected to raise our funding contribution that no attempt
	 * ended up spending (the request was refused, lost to a disconnect, or
	 * rolled back). Drained by the manager, which asks the wallet to release
	 * their pledges.
	 */
	private _danglingV2TopUpInputs: ISpliceWalletInput[] = [];
	// Our un-echoed tx_abort of a RECORDED v2 open. Connection scoped: the
	// teardown happens only when the peer's echo confirms it heard the
	// abort; until then the attempt (and its durable record) stays fully
	// live, because a lost abort leaves the peer holding our verified
	// commitment_signed and possibly a completable funding tx. A disconnect
	// forgets the abort and the attempt resumes over reestablish.
	private _v2AbortPending = false;
	// Our un-echoed tx_abort that unwound an ACCEPTED RBF request while the
	// recorded attempt stays fully live (handleTxAckRbf's failure arms). The
	// peer rolls back to the shared previous attempt and echoes; until that
	// echo a new RBF or operator abort would overlap the exchange, and the
	// delayed echo would then be taken for the newer abort's answer (tearing
	// down an attempt the peer rolled back to keep). While set, the
	// tx_signatures release is frozen like the other exchange latches; the
	// echo clears it and re-drives the release. Connection scoped: a
	// disconnect forgets it and both sides converge over reestablish.
	private _v2RollbackAbortPending = false;
	// The splice transaction once built and partially/fully signed: the tx, the
	// index of the shared 2-of-2 funding input, the new funding output index, the
	// old funding witness script, and our signature on the shared input.
	private _spliceTx: {
		tx: import('bitcoinjs-lib').Transaction;
		sharedInputIndex: number;
		newFundingOutputIndex: number;
		oldWitnessScript: Buffer;
		localSig: Buffer;
		// Witnesses we produced for our own wallet inputs (splice-in), in
		// tx-input order, and the input indices they were applied to.
		ourWalletWitnesses: Buffer[][];
		ourWalletInputIndices: number[];
	} | null = null;
	// ─── Taproot cooperative close (MuSig2 key-spend) ───
	// All in-memory only, NEVER persisted: BOLT 2 retransmits shutdown on
	// reestablish and each retransmission carries a FRESH MuSig2 closing nonce
	// (LND does the same), so a reconnect/restart simply restarts the closing
	// session. _ourClosingNonce is the EXACT object returned by generateNonce —
	// the musig library keys the secret nonce by object identity, so it must
	// never be copied before signing.
	private _ourClosingNonce: Uint8Array | null = null;
	private _remoteClosingNonce: Buffer | null = null;
	// Sign-once latch: our closing nonce signs exactly ONE sighash. Set when we
	// produce our closing partial; cleared only when fresh nonces arrive.
	private _hasSignedClosing = false;
	/** Live closing feerate (sat/kw) injected by the manager; ephemeral. */
	private _closingFeeratePerKw: number | null = null;
	// Opaque cache managed by the ChannelManager: the MuSig2 signing session,
	// unsigned closing tx and our partial at a specific fee. Invalidated here
	// whenever the nonces refresh (the channel owns the nonce lifecycle).
	private _taprootClosingCache: ITaprootClosingCache | null = null;
	private _currentBlockHeight = 0;
	private _channelKeyIndex: number | null = null;
	// Funding cap for this channel's open/splice validation: 2^24 sat (BOLT 2)
	// unless the ChannelManager lifted it because option_wumbo was negotiated
	// with the peer. In-memory only; the manager re-derives it per operation.
	private _maxFundingSatoshis: bigint = MAX_FUNDING_SATOSHIS;

	constructor(state: IChannelState, signer?: ISigner) {
		this._state = state;
		this._signer = signer || null;
	}

	/**
	 * Set the funding cap used to validate opens and splices on this channel
	 * (lifted above 2^24 sat only when option_wumbo was negotiated).
	 */
	setMaxFundingSatoshis(max: bigint): void {
		this._maxFundingSatoshis = max;
	}

	/**
	 * Get the per-channel key derivation index (null if using shared keys).
	 */
	get channelKeyIndex(): number | null {
		return this._channelKeyIndex;
	}

	/**
	 * Set the per-channel key derivation index.
	 */
	set channelKeyIndex(value: number | null) {
		this._channelKeyIndex = value;
	}

	/**
	 * Set or update the channel signer (used for commitment signature verification).
	 */
	setSigner(signer: ISigner): void {
		this._signer = signer;
	}

	/**
	 * Get the channel's signer. Returns null if no signer has been set.
	 */
	getSigner(): ISigner | null {
		return this._signer;
	}

	getState(): ChannelState {
		return this._state.state;
	}

	getChannelId(): Buffer | null {
		return this._state.channelId;
	}

	/**
	 * BOLT 2: whether we have pending updates not yet committed to the remote and
	 * therefore owe a commitment_signed. Used to avoid re-committing an unchanged
	 * state (which loops and reuses stale per-commitment points).
	 */
	needsCommitment(): boolean {
		return this._state.needsCommitment === true;
	}

	/**
	 * Revocations received from the peer (the next remote revocation index).
	 * Legacy states persisted before remoteRevocationNumber existed are
	 * assumed in sync (every signed commitment revoked) — exactly the
	 * assumption the pre-counter code baked in everywhere.
	 */
	private _remoteRevocationCount(): bigint {
		return (
			this._state.remoteRevocationNumber ?? this._state.remoteCommitmentNumber
		);
	}

	/**
	 * The revocation count to validate an INCOMING revoke_and_ack against.
	 * Legacy states default to remoteCommitmentNumber - 1: the historical
	 * behavior treated every incoming revoke_and_ack as revoking the
	 * last-signed commitment.
	 */
	private _remoteRevocationCountForRaa(): bigint {
		if (this._state.remoteRevocationNumber !== undefined) {
			return this._state.remoteRevocationNumber;
		}
		return this._state.remoteCommitmentNumber > 0n
			? this._state.remoteCommitmentNumber - 1n
			: 0n;
	}

	/**
	 * BOLT 2 commitment-round alternation: true while a commitment_signed we
	 * sent has not been answered by the peer's revoke_and_ack. Signing another
	 * commitment in that window desyncs the shachain index bookkeeping (which
	 * binds each incoming revoke_and_ack to one outstanding commitment), can
	 * bake a staged update_fee into a commitment the peer does not expect yet,
	 * and outruns the single-slot commitment_signed retransmission cache used
	 * on reestablish. Callers defer signing until the revoke_and_ack arrives.
	 */
	isAwaitingRemoteRevocation(): boolean {
		return this._remoteRevocationCount() < this._state.remoteCommitmentNumber;
	}

	getTemporaryChannelId(): Buffer {
		return this._state.temporaryChannelId;
	}

	getRole(): ChannelRole {
		return this._state.role;
	}

	getBalances(): { localMsat: bigint; remoteMsat: bigint } {
		return {
			localMsat: this._state.localBalanceMsat,
			remoteMsat: this._state.remoteBalanceMsat
		};
	}

	getFundingSatoshis(): bigint {
		return this._state.fundingSatoshis;
	}

	getCommitmentNumbers(): { local: bigint; remote: bigint } {
		return {
			local: this._state.localCommitmentNumber,
			remote: this._state.remoteCommitmentNumber
		};
	}

	getFullState(): IChannelState {
		return this._state;
	}

	/**
	 * Update the current block height for CLTV validation on incoming HTLCs.
	 */
	setBlockHeight(height: number): void {
		this._currentBlockHeight = height;
	}

	/**
	 * Record the fully-signed mutual-close transaction (hex) we broadcast at
	 * cooperative-close agreement. Persisted with the channel state so a restart
	 * in the pre-confirmation window can rebroadcast it and re-arm the funding
	 * watch (see LightningNode.restoreChainWatches).
	 */
	recordCooperativeCloseTx(txHex: string): void {
		this._state.lastCooperativeCloseTxHex = txHex;
	}

	/**
	 * Record why WE are closing this channel (persisted with channel state).
	 * Write-once for terminal closes: once the channel is FORCE_CLOSED or
	 * CLOSED the recorded reason describes the close that actually happened,
	 * so a later rebroadcast or duplicate API call must not relabel it.
	 * Returns whether the reason was written.
	 */
	recordCloseReason(reason: ChannelCloseReason): boolean {
		if (
			this._state.state === ChannelState.FORCE_CLOSED ||
			this._state.state === ChannelState.CLOSED
		) {
			return false;
		}
		if (this._state.closeReason === reason) return false;
		this._state.closeReason = reason;
		return true;
	}

	/** Undo a recordCloseReason whose close was refused. */
	clearCloseReason(): void {
		delete this._state.closeReason;
	}

	// ─────────────── Opening (Opener) ───────────────

	/**
	 * Initiate opening a channel. Sends open_channel.
	 * @param chainHash - Optional chain hash (defaults to Bitcoin mainnet)
	 * @param preferAnchors - If true, negotiate option_anchors_zero_fee_htlc_tx
	 */
	initiateOpen(
		chainHash?: Buffer,
		preferAnchors?: boolean,
		preferTaproot?: boolean
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NONE) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot initiate open: wrong state'
				}
			];
		}

		const maxHtlcErr = validateU64(
			this._state.localConfig.maxHtlcValueInFlightMsat,
			'max_htlc_value_in_flight_msat'
		);
		if (maxHtlcErr) {
			return [{ type: ChannelActionType.ERROR, message: maxHtlcErr }];
		}

		const firstPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			0n
		);

		// Build channel_type TLV.
		//
		// For simple taproot channels LND validates the channel_type with
		// OnlyContains(SimpleTaprootChannelsRequiredStaging) — an EXACT match on a
		// single bit (180). The taproot bit implies anchor-style commitments and
		// static_remotekey, so those bits MUST NOT also appear; any extra bit makes
		// LND reject with "requested channel type not supported" (verified live vs
		// lnd v0.20). Non-taproot keeps static_remotekey (bit 12) +
		// option_anchors_zero_fee_htlc_tx (bit 22) when requested.
		const channelTypeFlags = FeatureFlags.empty();
		if (preferTaproot) {
			channelTypeFlags.setCompulsory(Feature.OPTION_TAPROOT);
		} else {
			channelTypeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			if (preferAnchors) {
				channelTypeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			}
		}
		// Trusted-peer zero-conf: the intent must be carried in channel_type
		// (BOLT 2 feature 50) or the peer treats this as an ordinary open and
		// waits for confirmation. BOLT 9 makes option_zeroconf depend on
		// option_scid_alias, and a feature vector MUST include its transitive
		// dependencies, so both bits ride together. Note the extra bits make an
		// LND taproot peer reject the type (exact-match validation); zero-conf
		// opens are only ever made toward trusted peers, where that combination
		// does not arise.
		const zeroConf = this._state.zeroConfEnabled && this._state.trustedPeer;
		if (zeroConf) {
			channelTypeFlags.setCompulsory(Feature.SCID_ALIAS);
			channelTypeFlags.setCompulsory(Feature.ZERO_CONF);
		}
		const channelType = channelTypeFlags.toBuffer();
		this._state.channelType = channelType;

		const channelReserve = computeChannelReserve(
			this._state.fundingSatoshis,
			this._state.localConfig.dustLimitSatoshis
		);

		// max_htlc_value_in_flight_msat is advertised as configured, NOT
		// clamped to capacity: the advertisement is immutable for the life of
		// the channel while capacity is not (splice-in), so clamping would
		// bake the initial capacity in as a permanent ceiling. Over-capacity
		// values are interop-safe (CLN always advertises U64 max); peers take
		// min(capacity, value) and balance/reserve rules bound what can
		// actually be in flight.
		const msg: IOpenChannelMessage = {
			chainHash: chainHash || BITCOIN_CHAIN_HASH,
			temporaryChannelId: this._state.temporaryChannelId,
			fundingSatoshis: this._state.fundingSatoshis,
			pushMsat: this._state.pushMsat,
			dustLimitSatoshis: this._state.localConfig.dustLimitSatoshis,
			maxHtlcValueInFlightMsat:
				this._state.localConfig.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: channelReserve,
			htlcMinimumMsat: this._state.localConfig.htlcMinimumMsat,
			feeratePerKw: this._state.localConfig.feeratePerKw,
			toSelfDelay: this._state.localConfig.toSelfDelay,
			maxAcceptedHtlcs: this._state.localConfig.maxAcceptedHtlcs,
			fundingPubkey: this._state.localBasepoints.fundingPubkey,
			revocationBasepoint: this._state.localBasepoints.revocationBasepoint,
			paymentBasepoint: this._state.localBasepoints.paymentBasepoint,
			delayedPaymentBasepoint:
				this._state.localBasepoints.delayedPaymentBasepoint,
			htlcBasepoint: this._state.localBasepoints.htlcBasepoint,
			firstPerCommitmentPoint: firstPoint,
			// announce_channel bit. Simple taproot channels MUST be unannounced —
			// LND rejects a public taproot channel ("taproot channel type for public
			// channel"), so force the private flag for taproot. Same for zero-conf:
			// BOLT 2 forbids a channel_type containing option_scid_alias when
			// announce_channel is set.
			channelFlags: preferTaproot || zeroConf ? 0x00 : 0x01,
			channelType
		};

		// Keep our own record in step with what went on the wire, so the
		// announcement machinery never tries to announce a private channel.
		if (zeroConf) {
			this._state.announceChannel = false;
		}

		// option_taproot: attach our MuSig2 public nonce for the first commitment.
		if (preferTaproot) {
			msg.nextLocalNonce = this._ensureLocalFundingNonce();
		}

		// Store our first per-commitment point in the basepoints
		this._state.localBasepoints = {
			...this._state.localBasepoints,
			firstPerCommitmentPoint: firstPoint
		};

		const error = validateOpenChannelParams(msg, this._maxFundingSatoshis);
		if (error) {
			return [{ type: ChannelActionType.ERROR, message: error }];
		}

		// The reserve we just advertised IS the reserve we enforce on the peer:
		// localConfig.channelReserveSatoshis is what handleUpdateAddHtlc and
		// handleUpdateFee require the remote to keep, and what handleAcceptChannel
		// passes to validateAcceptChannelParams as the value we proposed. Left at
		// the config default it is a flat 10,000 that only coincides with the wire
		// value at exactly 1,000,000 sat: below that we refuse the peer's
		// spec-legal HTLCs, above it we let the peer sit under the reserve it
		// promised us. Recorded after the last refusal arm, so an open we never
		// send leaves enforcement untouched.
		this._state.localConfig = {
			...this._state.localConfig,
			channelReserveSatoshis: channelReserve
		};
		this._state.channelReserveVersion = ENFORCED_RESERVE_VERSION;

		this._state.state = ChannelState.SENT_OPEN;
		return [sendMsg(MessageType.OPEN_CHANNEL, encodeOpenChannelMessage(msg))];
	}

	/**
	 * option_taproot: DETERMINISTICALLY derive our MuSig2 verification nonce for a
	 * given local commitment height. The returned object is the secret-handle the
	 * library keys by identity; deriving it from a fixed sessionId makes the SAME
	 * (public + secret) nonce reproducible after a reconnect OR a restart, so the
	 * pre-reconnect commitment stays force-closeable (this mirrors how LND derives
	 * taproot verification nonces). The sessionId is an HMAC of our per-commitment
	 * SEED — a root secret the peer never learns — keyed by the height, so every
	 * height gets a unique, secret, reproducible nonce.
	 *
	 * SAFETY (no nonce reuse): the verification nonce for height H is used to SIGN
	 * exactly one thing — our own commitment at height H, and only at force-close
	 * (see forceClose). It signs that single sighash under the one peer signing
	 * nonce bound to height H (remoteSigningNonce, persisted), so the challenge is
	 * fixed and the same secret nonce never signs two different challenges. During
	 * normal operation only its PUBLIC part is shared (partialVerify is a public
	 * op). The per-signature SIGNING nonce used when WE co-sign the peer's
	 * commitment is a SEPARATE, fresh-random nonce — never derived here.
	 */
	private _deriveVerificationNonce(height: bigint): Uint8Array {
		const heightBuf = Buffer.alloc(8);
		heightBuf.writeBigUInt64BE(height);
		const sessionId = crypto
			.createHmac('sha256', this._state.localPerCommitmentSeed)
			.update(Buffer.from('beignet-taproot-verification-nonce', 'utf8'))
			.update(heightBuf)
			.digest();
		return generateNonce({
			publicKey: this._state.localBasepoints.fundingPubkey,
			sessionId
		});
	}

	/**
	 * Taproot coop close: generate a FRESH single-use closing nonce for the
	 * shutdown we are about to send, resetting the closing session (cache,
	 * partial, sign-once latch). Fresh-random (not derived): each shutdown
	 * (re)transmission starts a new closing session, mirroring LND, and the
	 * nonce secret lives only as long as this connection's negotiation.
	 * Returns the 66-byte public part for the shutdown TLV.
	 */
	private _refreshOurClosingNonce(): Buffer {
		this._ourClosingNonce = generateNonce({
			publicKey: this._state.localBasepoints.fundingPubkey,
			sessionId: crypto.randomBytes(32)
		});
		this._taprootClosingCache = null;
		this._hasSignedClosing = false;
		return Buffer.from(this._ourClosingNonce);
	}

	/**
	 * Taproot coop close: adopt the peer's closing nonce from its shutdown
	 * TLV. A (re)transmitted shutdown carries a fresh nonce, which invalidates
	 * any in-flight closing session built on the previous one.
	 */
	private _adoptRemoteClosingNonce(nonce: Buffer): void {
		this._remoteClosingNonce = Buffer.from(nonce);
		this._taprootClosingCache = null;
		this._hasSignedClosing = false;
	}

	/** Taproot coop close: nonce pair for the manager's signing session. */
	getClosingNonces(): {
		local: Uint8Array | null;
		remote: Buffer | null;
	} {
		return { local: this._ourClosingNonce, remote: this._remoteClosingNonce };
	}

	/** Taproot coop close: manager-owned session cache (see ITaprootClosingCache). */
	getTaprootClosingCache(): ITaprootClosingCache | null {
		return this._taprootClosingCache;
	}

	setTaprootClosingCache(cache: ITaprootClosingCache | null): void {
		this._taprootClosingCache = cache;
	}

	/**
	 * option_taproot: our verification nonce for the CURRENT local commitment
	 * (height = localCommitmentNumber). Re-derives deterministically if absent
	 * (e.g. dropped on reconnect, or after restore-from-disk) and returns the
	 * 66-byte public part for the wire. Idempotent.
	 */
	private _ensureLocalFundingNonce(): Buffer {
		if (!this._state.localNonce) {
			this._state.localNonce = this._deriveVerificationNonce(
				this._state.localCommitmentNumber
			);
		}
		return Buffer.from(this._state.localNonce);
	}

	/**
	 * option_taproot: our verification nonce for the NEXT local commitment
	 * (height = localCommitmentNumber + 1), advertised one step ahead
	 * (channel_ready / revoke_and_ack / channel_reestablish). Re-derives
	 * deterministically if absent. Idempotent — re-advertises the SAME nonce.
	 */
	private _ensureLocalNextNonce(): Buffer {
		if (!this._state.localNextNonce) {
			this._state.localNextNonce = this._deriveVerificationNonce(
				this._state.localCommitmentNumber + 1n
			);
		}
		return Buffer.from(this._state.localNextNonce);
	}

	/**
	 * option_taproot: verify the peer's 98-byte partial_signature_with_nonce (a
	 * MuSig2 partial signature over OUR initial commitment #0 || the peer's
	 * single-use signing nonce) carried in funding_created/funding_signed, and on
	 * success store it as remoteCommitmentSignature + remoteSigningNonce for later
	 * aggregation into the key-spend witness. Returns an error string on failure,
	 * or null on success.
	 */
	private _verifyAndStoreRemotePartial(
		partialSignatureWithNonce: Buffer | undefined,
		ourPublicNonce: Uint8Array | undefined,
		commitmentNumber: bigint
	): string | null {
		if (!partialSignatureWithNonce || partialSignatureWithNonce.length !== 98) {
			return 'Taproot commitment message missing a valid partial_signature_with_nonce';
		}
		if (!ourPublicNonce || !this._state.remoteBasepoints) {
			return 'Cannot verify taproot partial: missing local verification nonce or remote basepoints';
		}
		const theirPartial = Buffer.from(partialSignatureWithNonce.subarray(0, 32));
		const theirSigningNonce = Buffer.from(
			partialSignatureWithNonce.subarray(32, 98)
		);
		const localPerCommitmentPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			commitmentNumber
		);
		let valid: boolean;
		try {
			valid = verifyRemoteCommitmentPartial(
				this._state,
				theirPartial,
				ourPublicNonce,
				theirSigningNonce,
				localPerCommitmentPoint,
				commitmentNumber
			);
		} catch {
			// A 98-byte partial whose 66-byte nonce halves are not decodable
			// curve points, or whose 32-byte scalar is out of range, makes the
			// musig library THROW ('Unexpected public nonce at infinity',
			// 'Invalid sig') rather than return false. Uncaught, that throw
			// escaped every refusal arm above this helper all the way to
			// ChannelManager.handleMessage's catch: no wire error, no unwind,
			// a dead open nobody was told about (issue 415). Defense in depth
			// behind verifyRemoteCommitmentPartial's own catch. The exception
			// text is deliberately NOT included: this reason travels verbatim
			// in BOLT 1 error data, and library internals are neither a stable
			// wire contract nor the peer's business.
			return 'Invalid taproot partial signature';
		}
		if (!valid) {
			return 'Invalid taproot partial signature';
		}
		this._state.remoteCommitmentSignature = theirPartial;
		this._state.remoteSigningNonce = theirSigningNonce;
		return null;
	}

	/**
	 * option_taproot: verify + store the peer's partial over our INITIAL commitment
	 * (#0), carried in funding_created/funding_signed. The verification nonce here
	 * is our funding nonce (localNonce), seeded by open_channel/accept_channel.
	 */
	private _acceptFundingPartial(
		partialSignatureWithNonce?: Buffer
	): string | null {
		return this._verifyAndStoreRemotePartial(
			partialSignatureWithNonce,
			this._state.localNonce,
			0n
		);
	}

	/**
	 * Handle accept_channel from remote (opener side).
	 */
	handleAcceptChannel(msg: IAcceptChannelMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.SENT_OPEN) {
			// Deliberately LOCAL-only, the carve-out handleOpenChannel and
			// handleOpenChannel2 make for the same reason: this guard can only fire
			// on a channel that already has a life. A v1 opener stays keyed by this
			// temporary id through SENT_FUNDING_CREATED and until createFunding
			// promotes it, so the realistic producer is a duplicated or late
			// accept_channel for an open that has already advanced, which is exactly
			// what a retransmitting peer sends. A wire error scoped to that id would
			// cancel an open the peer believes is healthy. Every refusal of a LIVE
			// accept_channel below is wire-visible instead (issue 393).
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected accept_channel',
					cleanup: 'none'
				}
			];
		}

		if (!msg.temporaryChannelId.equals(this._state.temporaryChannelId)) {
			// Also LOCAL-only, and for a different reason. ChannelManager routes
			// accept_channel by msg.temporaryChannelId into tempChannels, so reaching
			// this arm means the map key and the channel's own id disagree: an
			// internal routing inconsistency, or a caller handing this Channel a
			// message belonging to another open. Either way the id in the message is
			// one we do not own, and answering under it would cancel a stranger's
			// negotiation. This arm is also what makes msg.temporaryChannelId equal
			// to ours for every arm below.
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'temporary_channel_id mismatch',
					cleanup: 'none'
				}
			];
		}

		// Every refusal below must reach the ACCEPTOR too (BOLT 2 negotiation
		// cancellation, BOLT 1 error): a local ERROR action is never put on the
		// wire, so it deletes our half while the acceptor sits in SENT_ACCEPT
		// holding a burnt key index and a retained temporary channel, waiting for a
		// funding_created that is never coming (issue 393).
		//
		// Scoped to OUR temporary id, not the message's. generateTemporaryChannelId
		// produced it, so it is 32 bytes and non-zero by construction and nothing a
		// peer can steer, and the guard above has just proved the two are equal. It
		// is the id the acceptor's side keys this open by and the one
		// ChannelManager keys tempChannels by.
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(this._state.temporaryChannelId, reason);

		// Validate the acceptor's parameters against what WE proposed in
		// open_channel BEFORE adopting them. Without this an adversarial acceptor
		// could set e.g. an unbounded dust_limit that trims our to_remote output to
		// fees on every commitment we sign (FS-1). The values we proposed live in
		// channel state.
		const acceptError = validateAcceptChannelParams(
			{
				temporaryChannelId: this._state.temporaryChannelId,
				dustLimitSatoshis: this._state.localConfig.dustLimitSatoshis,
				channelReserveSatoshis: this._state.localConfig.channelReserveSatoshis,
				fundingSatoshis: this._state.fundingSatoshis
			},
			msg
		);
		if (acceptError) {
			return refuse(`Invalid accept_channel: ${acceptError}`);
		}

		// Adopted before the channel-type, zero_conf and nonce arms below, so a
		// refusal there leaves a mutated state object. What makes that safe is what
		// makes it safe in handleOpenChannel: the ERROR action drops the temporary
		// channel entirely (removeCurrentTempChannel), and a v1 opener is not
		// promoted out of tempChannels until createFunding, so nothing seeded here
		// ever reaches a live channel.
		this._state.remoteConfig = {
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: msg.channelReserveSatoshis,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: this._state.localConfig.feeratePerKw
		};

		// Store remote basepoints
		this._state.remoteBasepoints = {
			fundingPubkey: msg.fundingPubkey,
			revocationBasepoint: msg.revocationBasepoint,
			paymentBasepoint: msg.paymentBasepoint,
			delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
			htlcBasepoint: msg.htlcBasepoint,
			firstPerCommitmentPoint: msg.firstPerCommitmentPoint
		};

		// BOLT 2: when the channel type is option_zeroconf the accepter MUST set
		// minimum_depth to zero. We forced 0 locally when initiating the trusted
		// open; a peer answering with a confirmation wait is a state-machine
		// disagreement to surface, not to paper over.
		if (
			this._state.channelType &&
			FeatureFlags.fromBuffer(this._state.channelType).hasFeature(
				Feature.ZERO_CONF
			)
		) {
			if (msg.minimumDepth !== 0) {
				return refuse(
					`zero_conf accept_channel must use minimum_depth 0, got ${msg.minimumDepth}`
				);
			}
		} else {
			this._state.minimumDepth = msg.minimumDepth;
		}
		this._state.remoteCurrentPerCommitmentPoint = msg.firstPerCommitmentPoint;

		// Validate channel type if provided — compare semantic feature bits,
		// not raw buffer bytes, to handle different-length encodings of the same features
		if (msg.channelType && this._state.channelType) {
			const localBits = FeatureFlags.fromBuffer(
				this._state.channelType
			).listSetBits();
			const remoteBits = FeatureFlags.fromBuffer(msg.channelType).listSetBits();
			if (
				localBits.length !== remoteBits.length ||
				!localBits.every((b, i) => b === remoteBits[i])
			) {
				return refuse('Channel type mismatch in accept_channel');
			}
		} else if (this._state.channelType && !msg.channelType) {
			// BOLT 2: if open_channel set channel_type, accept_channel MUST set it
			// to the exact same type. An omission is a violation, not an implicit
			// agreement — silently keeping our own type risks the two sides
			// building different commitment formats.
			return refuse(
				'accept_channel omitted channel_type after open_channel set it'
			);
		}
		if (msg.channelType) {
			this._state.channelType = msg.channelType;
		}

		// option_taproot: record the acceptor's funding nonce. Our own nonce was
		// generated and stored when we sent open_channel.
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.nextLocalNonce || msg.nextLocalNonce.length !== 66) {
				return refuse(
					'Taproot accept_channel missing a valid next_local_nonce'
				);
			}
			this._state.remoteNonce = msg.nextLocalNonce;
		}

		this._state.state = ChannelState.SENT_ACCEPT;
		return [];
	}

	/**
	 * Create the funding transaction and send funding_created.
	 * Called by the opener after accept_channel, once the funding tx is ready.
	 */
	createFundingCreated(
		fundingTxid: Buffer,
		fundingOutputIndex: number,
		signature: Buffer,
		partialSignatureWithNonce?: Buffer
	): ChannelAction[] {
		if (this._state.state !== ChannelState.SENT_ACCEPT) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot create funding: wrong state'
				}
			];
		}

		this._state.fundingTxid = fundingTxid;
		this._state.fundingOutputIndex = fundingOutputIndex;

		// Derive permanent channel ID
		this._state.channelId = deriveChannelId(fundingTxid, fundingOutputIndex);

		// option_taproot: the initial commitment is co-signed with a MuSig2 partial
		// signature carried in partial_signature_with_nonce; the fixed 64-byte
		// signature field is all-zero.
		const taproot = isTaprootChannel(this._state.channelType);
		if (
			taproot &&
			(!partialSignatureWithNonce || partialSignatureWithNonce.length !== 98)
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Taproot funding_created requires a partial_signature_with_nonce'
				}
			];
		}

		const msg: IFundingCreatedMessage = {
			temporaryChannelId: this._state.temporaryChannelId,
			fundingTxid,
			fundingOutputIndex,
			signature: taproot ? Buffer.alloc(64) : signature,
			partialSignatureWithNonce: taproot ? partialSignatureWithNonce : undefined
		};

		this._state.state = ChannelState.SENT_FUNDING_CREATED;
		return [
			sendMsg(MessageType.FUNDING_CREATED, encodeFundingCreatedMessage(msg))
		];
	}

	/**
	 * Handle funding_signed from remote (opener side).
	 */
	handleFundingSigned(msg: IFundingSignedMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.SENT_FUNDING_CREATED) {
			// Deliberately LOCAL-only, the same carve-out the three handlers above
			// make. A replayed funding_signed is an ordinary retransmission shape,
			// and by the time one arrives this side may already be
			// AWAITING_FUNDING_CONFIRMED with the funding transaction broadcast: a
			// wire error there would kill a channel that is genuinely opening. Every
			// refusal of a LIVE funding_signed below is wire-visible instead
			// (issue 393).
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected funding_signed',
					cleanup: 'none'
				}
			];
		}

		if (this._state.channelId && !msg.channelId.equals(this._state.channelId)) {
			// Also LOCAL-only. ChannelManager resolves funding_signed BY
			// msg.channelId (findChannelByChannelId, then the temp scan), so reaching
			// this arm means the id it resolved through and the channel's own id
			// disagree. The id in the message is one we do not own.
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'channel_id mismatch in funding_signed',
					cleanup: 'none'
				}
			];
		}

		// Every refusal below must reach the ACCEPTOR too: a local ERROR action is
		// never put on the wire, so it leaves the acceptor in
		// AWAITING_FUNDING_CONFIRMED waiting for a funding transaction that will
		// never be broadcast (issue 393). Worse here than anywhere else in the
		// handshake, because createFunding has already promoted this channel out of
		// tempChannels, so the local ERROR's removeCurrentTempChannel is a no-op and
		// nothing at all happens today.
		//
		// Scoped to our OWN derived id, not msg.channelId. deriveChannelId built it
		// from our own funding txid, so it is 32 bytes by construction and nothing a
		// peer can steer, whereas the mismatch guard above only compares
		// msg.channelId when ours is set. It is also the id the ACCEPTOR now keys
		// this channel by: a successful funding_created promoted its side to the
		// permanent id. The temporaryChannelId fallback is unreachable in
		// SENT_FUNDING_CREATED (createFundingCreated is the only way in and always
		// derives the id) and exists only for the type.
		//
		// Deliberately the plain refusal shape and NOT _failChannelWithWireError,
		// even though a permanent id exists by now. Nothing is on chain:
		// AUTHORIZE_FUNDING_BROADCAST is the only signal that permits the broadcast
		// and no arm here reaches it, so a force close would be a fiction that
		// prepareForceClose refuses anyway for want of a remote signature, leaving
		// only a misleading CHANNEL_FAILED_FORCE_CLOSE_FAILED. The persisted ERRORED
		// row would be worse: this channel has never been persisted, no funding
		// watch was ever armed, and nothing reaps such a row. And that helper
		// persists FIRST, so a failed persist would withhold the very error this
		// arm exists to send.
		//
		// cleanup 'lifecycle', which is what makes the local half work at all here.
		// createFunding promoted this channel to its PERMANENT id before a queued
		// funding_signed could arrive, so the default temporary-id drop finds
		// nothing and the opener would sit in this.channels in
		// SENT_FUNDING_CREATED forever: refused at the peer, immortal locally. The
		// funding transaction was never authorized for broadcast, so dropping the
		// whole registration is the correct unwind.
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(
				this._state.channelId ?? this._state.temporaryChannelId,
				reason,
				'lifecycle'
			);

		// Verify the acceptor's signature on our INITIAL commitment (#0) BEFORE
		// broadcasting the funding transaction. Every other commitment path
		// verifies the remote signature; the initial one must too. Otherwise a
		// malicious acceptor sends a garbage funding_signed, we lock our entire
		// balance in the 2-of-2 funding output, and forceClose() builds an
		// invalid witness from the bad signature that can never confirm — funds
		// held hostage with no unilateral exit (BOLT 2 MUST).
		if (isTaprootChannel(this._state.channelType)) {
			// option_taproot: verify the acceptor's MuSig2 partial over our
			// commitment #0 and store it (with their signing nonce) for aggregation.
			const err = this._acceptFundingPartial(msg.partialSignatureWithNonce);
			if (err) {
				return refuse(err);
			}
		} else {
			// Cannot verify -> must not adopt: an unverified funding_signed
			// gives the channel no unilateral exit, and the funding broadcast
			// that follows would lock funds behind it.
			if (!this._signer || !this._state.remoteBasepoints) {
				// Our own defect, told anyway: blame does not change the acceptor's
				// problem, and it is otherwise left awaiting a funding transaction
				// that will never be broadcast.
				return refuse(
					'Cannot verify commitment signature in funding_signed: no signer or remote basepoints'
				);
			}
			const firstPerCommitmentPoint = getPerCommitmentPoint(
				this._state.localPerCommitmentSeed,
				0n
			);
			const valid = verifyRemoteCommitmentSig(
				this._state,
				this._signer,
				firstPerCommitmentPoint,
				msg.signature,
				0n
			);
			if (!valid) {
				return refuse('Invalid commitment signature in funding_signed');
			}

			// Store remote's commitment signature
			this._state.remoteCommitmentSignature = msg.signature;
		}
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);
		this._state.lastSignedCommitLeaseBlockheight =
			getLocalCommitmentLeaseBlockheight(this._state);

		this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;

		const actions: ChannelAction[] = [
			// Persist channel state immediately — funds are now at risk
			{ type: ChannelActionType.PERSIST_STATE }
		];

		// Watch for funding confirmation
		if (this._state.fundingTxid) {
			actions.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: this._state.fundingTxid,
				fundingOutputIndex: this._state.fundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});
			// AFTER the watch and never before: the outpoint has to be under
			// observation before the transaction that creates it can confirm.
			// This is the only signal that authorizes the broadcast, and it is
			// an action so that a failed persist can withhold it and a quorum
			// barrier can hold it. The peer's signature over our commitment #0
			// has just been verified above, which is precisely when BOLT 2
			// starts the obligation.
			actions.push({
				type: ChannelActionType.AUTHORIZE_FUNDING_BROADCAST,
				fundingTxid: this._state.fundingTxid
			});
		}

		// Zero-conf: immediately send channel_ready without waiting for confirmation
		if (this._state.zeroConfEnabled && this._state.trustedPeer) {
			const readyActions = this.fundingConfirmed();
			actions.push(...readyActions);
		}

		return actions;
	}

	// ─────────────── Opening (Acceptor) ───────────────

	/**
	 * Handle open_channel from remote (acceptor side).
	 * Returns the accept_channel response.
	 */
	handleOpenChannel(msg: IOpenChannelMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.NONE) {
			// Deliberately LOCAL-only, the same carve-out handleOpenChannel2 makes:
			// this guard can only fire on a channel that already has a life (a
			// replayed or misrouted open), and a wire error scoped to that id would
			// cancel whatever the peer still considers live. Every refusal of a
			// FRESH open below is wire-visible instead.
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected open_channel' }
			];
		}

		// The one id we cannot answer under. BOLT 1 reserves the all-zero
		// channel_id for "all channels with this peer", so the wire error every
		// arm below returns would tell the opener to fail all of them. Refused
		// locally instead, which is what makes the closure's "scoped to the id
		// the opener used" true for every caller: ChannelManager drops such an
		// open before it ever builds a Channel, and this covers anyone driving
		// the Channel directly. refuseWithWireError suppresses it a second time,
		// the way refuseInboundOpen does for the manager's callers; this arm
		// stays because it refuses AHEAD of every mutation below and says which
		// id was the problem.
		if (msg.temporaryChannelId.every((b) => b === 0)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'open_channel refused: temporary_channel_id is the reserved all-zero id'
				}
			];
		}

		// Every rejected inbound open_channel must reach the OPENER too (BOLT 2
		// negotiation cancellation, BOLT 1 error): a local ERROR action is never
		// put on the wire, so it deletes our half while the opener sits in
		// SENT_OPEN awaiting an accept_channel that never comes, retrying the
		// identical open because nothing told it to stop.
		//
		// Scoped to the id the OPENER used, which is the id its side keys the
		// pending open by and the one ChannelManager keys tempChannels by, so the
		// wire scope and the local cleanup can never name different entries. It is
		// also the only one guaranteed to be the 32 bytes encodeErrorMessage
		// demands, having been sliced from the wire by decodeOpenChannelMessage.
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(msg.temporaryChannelId, reason);

		// Peer-supplied, so the bounds that only apply to a value we did not
		// choose run too. ChannelManager.handleOpenChannel has already seeded
		// remoteConfig from this message; what makes a refusal here safe is that
		// the ERROR action drops the temporary channel entirely
		// (removeCurrentTempChannel), so nothing it seeded ever reaches a live
		// channel.
		const error = validatePeerOpenChannelParams(msg, this._maxFundingSatoshis);
		if (error) {
			return refuse(error);
		}

		// Store remote config
		this._state.remoteConfig = {
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: msg.channelReserveSatoshis,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: msg.feeratePerKw
		};

		// Store remote basepoints
		this._state.remoteBasepoints = {
			fundingPubkey: msg.fundingPubkey,
			revocationBasepoint: msg.revocationBasepoint,
			paymentBasepoint: msg.paymentBasepoint,
			delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
			htlcBasepoint: msg.htlcBasepoint,
			firstPerCommitmentPoint: msg.firstPerCommitmentPoint
		};

		this._state.remoteCurrentPerCommitmentPoint = msg.firstPerCommitmentPoint;
		this._state.fundingSatoshis = msg.fundingSatoshis;
		this._state.pushMsat = msg.pushMsat;
		this._state.localBalanceMsat = msg.pushMsat;
		this._state.remoteBalanceMsat = msg.fundingSatoshis * 1000n - msg.pushMsat;

		// BOLT 2: channel_flags bit 0 = announce_channel
		this._state.announceChannel = (msg.channelFlags & 0x01) !== 0;

		const firstPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			0n
		);
		this._state.localBasepoints = {
			...this._state.localBasepoints,
			firstPerCommitmentPoint: firstPoint
		};

		// Validate and store channel type from open_channel
		if (msg.channelType) {
			const proposedFlags = FeatureFlags.fromBuffer(msg.channelType);
			// Simple taproot channels carry ONLY the taproot bit (static_remotekey is
			// implied), so accept either an explicit static_remotekey or taproot.
			if (
				!proposedFlags.hasFeature(Feature.STATIC_REMOTE_KEY) &&
				!proposedFlags.hasFeature(Feature.OPTION_TAPROOT)
			) {
				return refuse('Proposed channel type must include static_remotekey');
			}
			// A zero_conf channel type commits us to minimum_depth 0 (BOLT 2), so
			// only accept it from peers in the trusted set (unconfirmed funding can
			// be double-spent by the opener). The flip is driven by the EXPLICIT
			// channel type, never by trust-set membership alone: a stale trusted
			// entry must not change how ordinary opens from that peer validate.
			if (proposedFlags.hasFeature(Feature.ZERO_CONF)) {
				if (!this._state.trustedPeer) {
					return refuse(
						'Proposed zero_conf channel type requires a trusted peer'
					);
				}
				this._state.zeroConfEnabled = true;
				this._state.minimumDepth = 0;
			}
			this._state.channelType = msg.channelType;
		} else {
			// If no channel type proposed, default to static_remotekey
			const defaultType = FeatureFlags.empty();
			defaultType.setCompulsory(Feature.STATIC_REMOTE_KEY);
			this._state.channelType = defaultType.toBuffer();
		}

		// BOLT 2 couplings for the accept_channel WE build: our channel_reserve
		// MUST be >= the opener's dust_limit (else the opener's below-reserve
		// balance could be trimmed as dust), so raise it if our formula lands
		// lower. And our dust_limit MUST be <= the opener's channel_reserve; we
		// will not lower our own dust floor, so reject the open instead of
		// emitting a non-compliant accept_channel the opener must then fail.
		//
		// Our OWN dust limit floors it too, because computeChannelReserve applies
		// its 20% cap last and can land under the very dust floor it starts from:
		// a 2,500-sat open against a 600-sat local dust limit yields 500. That
		// pairing breaks the rule this reserve exists to keep (each reserve above
		// both dust limits, see MAX_DUST_LIMIT_SATOSHIS in types.ts), leaving the
		// opener a reserve output that trims away in our own commitment, and LND
		// rejects such an accept_channel outright.
		const channelReserve = bigIntMax(
			computeChannelReserve(
				this._state.fundingSatoshis,
				this._state.localConfig.dustLimitSatoshis
			),
			bigIntMax(
				msg.dustLimitSatoshis,
				this._state.localConfig.dustLimitSatoshis
			)
		);
		if (
			this._state.localConfig.dustLimitSatoshis > msg.channelReserveSatoshis
		) {
			return refuse(
				`our dust_limit ${this._state.localConfig.dustLimitSatoshis} exceeds opener channel_reserve ${msg.channelReserveSatoshis}`
			);
		}

		// max_htlc_value_in_flight_msat is advertised as configured, not
		// clamped to the opener's capacity (see initiateOpen: the
		// advertisement outlives the current capacity).
		const acceptMaxHtlcErr = validateU64(
			this._state.localConfig.maxHtlcValueInFlightMsat,
			'max_htlc_value_in_flight_msat'
		);
		if (acceptMaxHtlcErr) {
			// Our own misconfiguration rather than the peer's fault, and told
			// anyway, exactly as handleOpenChannel2 tells it: blame does not change
			// the opener's problem, and a refusal it cannot see leaves it retrying
			// an open that can never be accepted. The text is a field name and a
			// protocol constant, and our configured value would have gone out in
			// accept_channel on the success path regardless.
			return refuse(acceptMaxHtlcErr);
		}

		const acceptMsg: IAcceptChannelMessage = {
			temporaryChannelId: this._state.temporaryChannelId,
			dustLimitSatoshis: this._state.localConfig.dustLimitSatoshis,
			maxHtlcValueInFlightMsat:
				this._state.localConfig.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: channelReserve,
			htlcMinimumMsat: this._state.localConfig.htlcMinimumMsat,
			minimumDepth: this._state.minimumDepth,
			toSelfDelay: this._state.localConfig.toSelfDelay,
			maxAcceptedHtlcs: this._state.localConfig.maxAcceptedHtlcs,
			fundingPubkey: this._state.localBasepoints.fundingPubkey,
			revocationBasepoint: this._state.localBasepoints.revocationBasepoint,
			paymentBasepoint: this._state.localBasepoints.paymentBasepoint,
			delayedPaymentBasepoint:
				this._state.localBasepoints.delayedPaymentBasepoint,
			htlcBasepoint: this._state.localBasepoints.htlcBasepoint,
			firstPerCommitmentPoint: firstPoint,
			channelType: this._state.channelType
		};

		// option_taproot: record the opener's funding nonce and return ours.
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.nextLocalNonce || msg.nextLocalNonce.length !== 66) {
				return refuse('Taproot open_channel missing a valid next_local_nonce');
			}
			this._state.remoteNonce = msg.nextLocalNonce;
			acceptMsg.nextLocalNonce = this._ensureLocalFundingNonce();
		}

		// Enforce what we just advertised (see initiateOpen). Recorded after the
		// last refusal arm, so an open we never accept leaves enforcement
		// untouched.
		this._state.localConfig = {
			...this._state.localConfig,
			channelReserveSatoshis: channelReserve
		};
		this._state.channelReserveVersion = ENFORCED_RESERVE_VERSION;

		this._state.state = ChannelState.SENT_ACCEPT;
		return [
			sendMsg(MessageType.ACCEPT_CHANNEL, encodeAcceptChannelMessage(acceptMsg))
		];
	}

	/**
	 * Handle funding_created from remote (acceptor side).
	 * Returns funding_signed response.
	 */
	handleFundingCreated(
		msg: IFundingCreatedMessage,
		signature: Buffer,
		partialSignatureWithNonce?: Buffer
	): ChannelAction[] {
		if (this._state.state !== ChannelState.SENT_ACCEPT) {
			// Deliberately LOCAL-only, the same carve-out handleOpenChannel and
			// handleAcceptChannel make: this guard can only fire on a channel that
			// already has a life, so its realistic producer is a duplicated or late
			// funding_created for an open that has already advanced. A wire error
			// scoped to that id would cancel a negotiation the opener believes is
			// healthy. Every refusal of a LIVE funding_created below is wire-visible
			// instead (issue 393).
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected funding_created',
					cleanup: 'none'
				}
			];
		}

		if (!msg.temporaryChannelId.equals(this._state.temporaryChannelId)) {
			// Also LOCAL-only. ChannelManager routes funding_created by
			// msg.temporaryChannelId into tempChannels, so reaching this arm means
			// the map key and the channel's own id disagree: an internal routing
			// inconsistency, or a caller handing this Channel a message belonging to
			// another open. The id in the message is one we do not own.
			// cleanup 'none': the manager drops the temporary channel for EVERY
			// local ERROR, so the default would delete the very negotiation this
			// guard exists to leave alone.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'temporary_channel_id mismatch',
					cleanup: 'none'
				}
			];
		}

		// Every refusal below must reach the OPENER too (BOLT 2 negotiation
		// cancellation, BOLT 1 error): a local ERROR action is never put on the
		// wire, so it deletes our half while the opener sits in
		// SENT_FUNDING_CREATED holding a built and signed funding transaction it
		// will never be told to abandon (issue 393).
		//
		// Scoped to the id the OPENER used, matching ChannelManager's own two
		// refusals at this exact stage (the channel-id-in-use arms) and the id
		// BOLT 2 still carries on funding_created. Deliberately NOT the permanent
		// channelId derived after verification below: that one is built from
		// PEER-SUPPLIED fundingTxid and fundingOutputIndex, so an opener quoting
		// an all-zero txid at output 0 derives an all-zero channel_id and would
		// turn this refusal into "fail every channel with me".
		// msg.temporaryChannelId equals our own self-generated id by the guard
		// above and cannot be steered.
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(msg.temporaryChannelId, reason);

		this._state.fundingTxid = msg.fundingTxid;
		this._state.fundingOutputIndex = msg.fundingOutputIndex;

		// Verify the opener's signature on our initial commitment (#0) before
		// sending funding_signed (BOLT 2 MUST: the acceptor validates the
		// funder's signature first). Same class of check as funding_signed/
		// commitment_signed; without it we'd persist an unverifiable initial
		// commitment we cannot force-close.
		const taproot = isTaprootChannel(this._state.channelType);
		if (taproot) {
			// option_taproot: verify the opener's MuSig2 partial over our
			// commitment #0 and store it (with their signing nonce) for aggregation.
			const err = this._acceptFundingPartial(msg.partialSignatureWithNonce);
			if (err) {
				return refuse(err);
			}
			if (
				!partialSignatureWithNonce ||
				partialSignatureWithNonce.length !== 98
			) {
				// Our own defect rather than the opener's fault, and told anyway,
				// exactly as handleOpenChannel tells its max_htlc_value_in_flight
				// misconfiguration: blame does not change the opener's problem, and a
				// refusal it cannot see leaves it holding a built, signed, unbroadcast
				// funding transaction forever.
				return refuse(
					'Taproot funding_signed requires a partial_signature_with_nonce'
				);
			}
		} else {
			// Cannot verify -> must not adopt: the funding_signed we return
			// commits us to the opener's funding tx, so an unverified opener
			// signature would leave this side with no unilateral exit.
			if (!this._signer || !this._state.remoteBasepoints) {
				// Our own defect, told anyway, for the reason given at the taproot arm
				// above.
				return refuse(
					'Cannot verify commitment signature in funding_created: no signer or remote basepoints'
				);
			}
			const firstPerCommitmentPoint = getPerCommitmentPoint(
				this._state.localPerCommitmentSeed,
				0n
			);
			const valid = verifyRemoteCommitmentSig(
				this._state,
				this._signer,
				firstPerCommitmentPoint,
				msg.signature,
				0n
			);
			if (!valid) {
				return refuse('Invalid commitment signature in funding_created');
			}

			// Store remote's commitment signature
			this._state.remoteCommitmentSignature = msg.signature;
		}
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);
		this._state.lastSignedCommitLeaseBlockheight =
			getLocalCommitmentLeaseBlockheight(this._state);

		// Adopt the peer-derived permanent id only after every refusal arm above
		// has passed: it is built from PEER-SUPPLIED fields (an all-zero txid at
		// output 0 derives an all-zero channel_id), so a refused funding_created
		// must leave getChannelId() null and let the manager's local-error emits
		// fall back to the temporary id, matching the wire refusal's scope.
		this._state.channelId = deriveChannelId(
			msg.fundingTxid,
			msg.fundingOutputIndex
		);

		const signedMsg: IFundingSignedMessage = {
			channelId: this._state.channelId,
			signature: taproot ? Buffer.alloc(64) : signature,
			partialSignatureWithNonce: taproot ? partialSignatureWithNonce : undefined
		};

		this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;

		const actions: ChannelAction[] = [
			// Persist channel state BEFORE sending funding_signed — funds are now at risk
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(
				MessageType.FUNDING_SIGNED,
				encodeFundingSignedMessage(signedMsg)
			),
			{
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: msg.fundingTxid,
				fundingOutputIndex: msg.fundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			}
		];

		// Zero-conf acceptor: send channel_ready right behind funding_signed
		// instead of waiting for confirmation, mirroring the opener, which
		// fast-tracks on funding_signed. Without this the acceptor never reaches
		// NORMAL until the funding tx confirms and the channel is unusable in
		// exactly the window zero-conf exists for.
		if (this._state.zeroConfEnabled && this._state.trustedPeer) {
			actions.push(...this.fundingConfirmed());
		}

		return actions;
	}

	// ─────────────── Channel Ready ───────────────

	/**
	 * Called when a funding transaction reaches minimum depth. Sends
	 * channel_ready. `confirmedTxid` (internal byte order) names WHICH
	 * attempt confirmed when the chain watcher tracks several (post-
	 * signatures RBF, issue #360); omitted means the current attempt.
	 */
	fundingConfirmed(confirmedTxid?: Buffer): ChannelAction[] {
		// Several attempts can confirm; a caller that does not say WHICH must
		// not have "the current one" guessed for it — adopting the wrong
		// attempt erases the real winner's candidacy. Internal flushes always
		// name the txid; this only catches ambiguous manual-chain calls.
		if (!confirmedTxid && this._state.v2PreviousAttempts?.length) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'ambiguous funding confirmation: multiple RBF attempts are tracked; pass the confirmed txid'
				}
			];
		}
		const prefix: ChannelAction[] = [];
		const current = this._state.v2InFlight;
		const isCurrentAttempt =
			!confirmedTxid ||
			(current
				? current.fundingTxid.equals(confirmedTxid)
				: !!this._state.fundingTxid?.equals(confirmedTxid));
		if (!isCurrentAttempt) {
			const previous = this._state.v2PreviousAttempts ?? [];
			const index = previous.findIndex((rec) =>
				rec.fundingTxid.equals(confirmedTxid!)
			);
			// A txid this open never produced: a stale callback, ignored.
			if (index < 0) return [];
			// Disconnected: the depth callback is one-shot, so record which
			// attempt confirmed durably; the next reestablish adopts it.
			if (this._state.state === ChannelState.AWAITING_REESTABLISH) {
				if (!previous[index].confirmed) {
					previous[index].confirmed = true;
					return [{ type: ChannelActionType.PERSIST_STATE }];
				}
				return [];
			}
			// The channel already failed and a SUPERSEDED attempt won the
			// race, so the exit it would broadcast spends a funding output
			// that can now never exist. Adopt the confirmed attempt (outpoint
			// + its commitment signature) so the close can be built against
			// the funding that is actually on chain, keep the terminal state,
			// and stamp the confirmation durably: the node's close re-drive
			// (and any restart) keys off the confirmed adopted record. No
			// ready flow and no abort.
			//
			// ERRORED belongs here as much as FORCE_CLOSED: prepareForceClose
			// accepts both, so a channel failed by a BOLT 1 error still owes
			// a unilateral exit. Falling through to the state gate below
			// dropped the confirmation silently and left no stamp, so the
			// adoption in prepareForceClose (which looks for a confirmed
			// previous attempt) could never rescue it either.
			if (
				this._state.state === ChannelState.FORCE_CLOSED ||
				this._state.state === ChannelState.ERRORED
			) {
				const adopted = previous[index];
				this._state.v2InFlight = adopted;
				this._state.v2PreviousAttempts = undefined;
				this._activateV2Record(adopted);
				adopted.confirmed = true;
				this._state.pendingFundingTxHex = undefined;
				return [{ type: ChannelActionType.PERSIST_STATE }];
			}
			if (
				this._state.state !== ChannelState.DUAL_FUNDING_V2 &&
				this._state.state !== ChannelState.AWAITING_TX_SIGNATURES &&
				this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
				this._state.state !== ChannelState.AWAITING_CHANNEL_READY
			) {
				return [];
			}
			// A superseded attempt won the race: adopt it and abandon
			// whatever negotiation the adoption kills, then fall through to
			// the ready flow (the adoption leaves AWAITING_FUNDING_CONFIRMED).
			prefix.push(...this._v2AdoptPreviousAttempt(index));
		} else if (
			this._state.state === ChannelState.DUAL_FUNDING_V2 &&
			current &&
			this._v2RecordIsStaleRollback()
		) {
			// The retained attempt confirmed mid-renegotiation. BOLT 2: "If
			// the previous transaction confirms in the middle of an RBF
			// attempt, the attempt MUST be abandoned." Roll back to the
			// confirmed attempt, abandon the renegotiation with tx_abort
			// (nothing of it was signed; the latch guard keeps BOLT 2's
			// single-abort rule), and fall through to the ready flow.
			const canAbort = !this._txAbortSent;
			this._rollbackToRetainedV2Attempt();
			prefix.push({ type: ChannelActionType.PERSIST_STATE });
			if (canAbort) {
				prefix.push(
					this._txAbort(
						this._v2ChannelId(),
						'the previous funding attempt confirmed; RBF abandoned'
					)
				);
			}
		}
		// Funding confirmation only drives action while we are still bringing the
		// channel up. For any later state (NORMAL, closing, reestablish, or already
		// closed) this is stale information — treat it as an idempotent no-op rather
		// than an error so chain-watcher reconciliation on restart stays quiet.
		if (
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY
		) {
			// A v2 open that cannot consume the confirmation yet (disconnected,
			// or its signature exchange still incomplete): the chain watcher's
			// depth callback is one-shot, so record it durably and let the
			// exchange completion or the next reestablish flush channel_ready
			// (mirrors markSpliceConfirmed for a splice that confirmed while
			// the channel could not send splice_locked).
			//
			// ERRORED is admitted for the same reason the v1 arm below records
			// fundingConfirmedLate (issue #413): a failed open never flushes
			// channel_ready, but the outpoint now provably exists, and every
			// decision that turns on that fact reads it back through
			// isFundingKnownOnChain. Without the stamp a failed v2 open can
			// watch its own funding reach depth and record nothing, so it
			// stays 'not on chain' forever and no exit is ever driven for it
			// (issue #463).
			if (
				this._state.v2InFlight &&
				!this._state.v2InFlight.confirmed &&
				(this._state.state === ChannelState.AWAITING_REESTABLISH ||
					this._state.state === ChannelState.AWAITING_TX_SIGNATURES ||
					this._state.state === ChannelState.ERRORED)
			) {
				this._state.v2InFlight.confirmed = true;
				return [...prefix, { type: ChannelActionType.PERSIST_STATE }];
			}
			// A v1 depth observation the ready flow cannot consume: the
			// zero-conf fast-track already ran it (NORMAL long before real
			// depth), or the channel has already failed. The callback is
			// one-shot, so record durably that the outpoint now exists. The
			// node's failure resolution (handleChannelErrored and the ERRORED
			// block backstop) keys off this to broadcast the exit it skipped
			// or would otherwise skip while the funding was not known on
			// chain (issue #413).
			if (!this._state.v2InFlight && !this._state.fundingConfirmedLate) {
				this._state.fundingConfirmedLate = true;
				return [...prefix, { type: ChannelActionType.PERSIST_STATE }];
			}
			return prefix;
		}
		// One attempt reached depth, so every other attempt of this open is
		// dead (each replacement double-spends all of its predecessors).
		this._state.v2PreviousAttempts = undefined;

		const secondPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			1n
		);

		// Generate SCID alias for private channels
		if (!this._state.scidAlias) {
			this._state.scidAlias = crypto.randomBytes(8);
		}

		const msg: IChannelReadyMessage = {
			channelId: this._state.channelId!,
			secondPerCommitmentPoint: secondPoint,
			shortChannelId: this._state.scidAlias
		};

		// option_taproot: seed the verification-nonce pipeline — advertise our nonce
		// for commitment #1 alongside second_per_commitment_point.
		if (isTaprootChannel(this._state.channelType)) {
			msg.nextLocalNonce = this._ensureLocalNextNonce();
		}

		this._state.localChannelReady = true;

		if (this._state.remoteChannelReady) {
			this._state.state = ChannelState.NORMAL;
			// The peer's channel_ready means it holds the complete funding tx,
			// so the v2 opening record has nothing left to resume or retransmit
			// (the funding tx itself stays in pendingFundingTxHex until depth).
			this._state.v2InFlight = null;
			return [
				...prefix,
				sendMsg(MessageType.CHANNEL_READY, encodeChannelReadyMessage(msg)),
				{
					type: ChannelActionType.CHANNEL_READY,
					channelId: this._state.channelId!
				}
			];
		}

		this._state.state = ChannelState.AWAITING_CHANNEL_READY;
		return [
			...prefix,
			sendMsg(MessageType.CHANNEL_READY, encodeChannelReadyMessage(msg))
		];
	}

	/**
	 * Handle channel_ready from remote.
	 */
	handleChannelReady(msg: IChannelReadyMessage): ChannelAction[] {
		// If channel_ready has already been exchanged in both directions, the
		// channel is established. A peer legitimately RETRANSMITS channel_ready on
		// reconnection (BOLT 2 §5), so a duplicate must be ignored — never failed —
		// regardless of the current lifecycle state (NORMAL, AWAITING_REESTABLISH,
		// closing, …). Treating it as an error here previously surfaced a spurious
		// "Unexpected channel_ready" on every reconnect of a live channel.
		if (this._state.localChannelReady && this._state.remoteChannelReady) {
			return [];
		}
		// BOLT 2 abandons an RBF attempt only for a VALID channel_ready, and
		// the point below is stored as commitment material, so validate it
		// before anything is abandoned or written. Checked here rather than
		// beside the assignment: the abandon arms roll a live replacement back
		// (and can put tx_abort on the wire), so a malformed message would
		// otherwise destroy a perfectly good attempt on its way to being
		// rejected.
		if (!isValidPublicKey(msg.secondPerCommitmentPoint)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'channel_ready has an invalid second_per_commitment_point'
				}
			];
		}
		// BOLT 2: "If a valid channel_ready message is received in the middle
		// of an RBF attempt, the attempt MUST be abandoned." The peer's ready
		// proves one of this open's attempts confirmed on its side (a normal
		// peer-first confirmation race); our own depth callback names WHICH
		// attempt and adopts it. Abandon the replacement negotiation here and
		// let the ready process against the resumed COMPLETED attempt. Both
		// arms are restricted to a completed rollback target so the resumed
		// state passes the gate below; anything else keeps the pre-existing
		// rejection.
		const prefix: ChannelAction[] = [];
		if (
			this._state.state === ChannelState.DUAL_FUNDING_V2 &&
			this._state.v2InFlight &&
			this._v2RecordIsStaleRollback() &&
			this._v2StateForRecord(this._state.v2InFlight) ===
				ChannelState.AWAITING_FUNDING_CONFIRMED
		) {
			// Mid-renegotiation: nothing of the replacement was signed, so
			// tx_abort is its lawful abandon signal (single-abort latch kept).
			const canAbort = !this._txAbortSent;
			this._rollbackToRetainedV2Attempt();
			prefix.push({ type: ChannelActionType.PERSIST_STATE });
			if (canAbort) {
				prefix.push(
					this._txAbort(
						this._v2ChannelId(),
						'channel_ready received; the RBF attempt is abandoned'
					)
				);
			}
		} else if (
			this._state.state === ChannelState.AWAITING_TX_SIGNATURES &&
			this._v2ReplacementAbandonable() &&
			this._v2StateForRecord(
				this._state.v2PreviousAttempts![
					this._state.v2PreviousAttempts!.length - 1
				]
			) === ChannelState.AWAITING_FUNDING_CONFIRMED
		) {
			// Post-swap unsigned replacement: same abandonment, resuming the
			// newest superseded attempt.
			const canAbort = !this._v2TxSigsReleased && !this._txAbortSent;
			this._popToPreviousV2Attempt();
			prefix.push({ type: ChannelActionType.PERSIST_STATE });
			if (canAbort) {
				prefix.push(
					this._txAbort(
						this._v2ChannelId(),
						'channel_ready received; the replacement is abandoned'
					)
				);
			}
		}
		if (
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY &&
			this._state.state !== ChannelState.SENT_FUNDING_CREATED &&
			this._state.state !== ChannelState.AWAITING_REESTABLISH
		) {
			// Per BOLT 2: if already NORMAL, just ignore duplicate channel_ready
			if (this._state.state === ChannelState.NORMAL) {
				return [];
			}
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected channel_ready' }
			];
		}

		this._state.remoteChannelReady = true;
		this._state.remoteNextPerCommitmentPoint = msg.secondPerCommitmentPoint;

		// option_taproot: the peer's commitment-#1 verification nonce seeds the
		// pipeline — it matches second_per_commitment_point (remoteNextPerCommitment-
		// Point), so we use it when we co-sign the peer's first post-funding
		// commitment. It is rotated forward thereafter by each revoke_and_ack.
		if (isTaprootChannel(this._state.channelType) && msg.nextLocalNonce) {
			if (msg.nextLocalNonce.length !== 66) {
				return [
					...prefix,
					{
						type: ChannelActionType.ERROR,
						message: 'Taproot channel_ready has an invalid next_local_nonce'
					}
				];
			}
			this._state.remoteNonce = msg.nextLocalNonce;
		}

		// Store remote's SCID alias if provided
		if (msg.shortChannelId) {
			this._state.remoteScidAlias = msg.shortChannelId;
		}

		if (this._state.localChannelReady) {
			this._state.state = ChannelState.NORMAL;
			// Mirror of fundingConfirmed: the peer's channel_ready means the v2
			// opening record has nothing left to resume or retransmit, and no
			// other attempt of this open can confirm any more.
			this._state.v2InFlight = null;
			this._state.v2PreviousAttempts = undefined;
			return [
				...prefix,
				{
					type: ChannelActionType.CHANNEL_READY,
					channelId: this._state.channelId!
				}
			];
		}

		this._state.state = ChannelState.AWAITING_CHANNEL_READY;
		return prefix;
	}

	// ─────────────── Normal Operation ───────────────

	/**
	 * Add an HTLC to the channel (locally offered).
	 */
	addHtlc(
		amountMsat: bigint,
		paymentHash: Buffer,
		cltvExpiry: number,
		onionRoutingPacket: Buffer,
		blindingPoint?: Buffer
	): ChannelAction[] {
		// Pending-lock (tx_signatures crossed both ways, splice_locked not yet):
		// update traffic has resumed per the splicing extension, and every add
		// is mirrored onto both fundings by the start_batch commitment round.
		if (
			this._state.state !== ChannelState.NORMAL &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot add HTLC: channel in ${this._state.state} state`
				}
			];
		}

		// A capsule-restored channel whose recency cannot be proven takes no NEW
		// HTLCs (issue #469). Its HTLC deadline backstops can never fire, since
		// every automatic close is refused for as long as the hold stands, and
		// an HTLC whose only on-chain enforcement this node has disarmed is a
		// bounded risk turning into an unbounded one: the peer can simply stall
		// and we have nothing to escalate to. Existing HTLCs still settle and
		// fail off chain, and the channel still closes cooperatively, which
		// needs no revocation and is therefore safe from a stale state.
		if (this._state.restoreRecencyUnproven === true) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot add HTLC: channel was restored from a Recovery Capsule ' +
						'and its state cannot be proven current, so its on-chain HTLC ' +
						'backstops are disabled'
				}
			];
		}

		// Reject during quiescence.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot add HTLC: channel is quiescing'
				}
			];
		}

		// BOLT 2: cltv_expiry MUST be < 500000000 (values at or above are
		// interpreted as unix timestamps, not block heights). Send-side check so
		// we never emit an update_add_htlc a conformant peer must fail.
		if (cltvExpiry >= 500_000_000) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `HTLC cltv_expiry ${cltvExpiry} is not a block height (>= 500000000)`
				}
			];
		}

		// Check amount exceeds minimum
		if (amountMsat < this._state.remoteConfig.htlcMinimumMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'HTLC amount below remote minimum'
				}
			];
		}

		// Check we don't exceed max pending HTLCs
		const pendingOffered = this.countPendingHtlcs(HtlcDirection.OFFERED);
		if (pendingOffered >= this._state.remoteConfig.maxAcceptedHtlcs) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Max pending HTLCs exceeded' }
			];
		}

		// Check total in-flight doesn't exceed max
		const totalInFlight =
			this.totalInFlightMsat(HtlcDirection.OFFERED) + amountMsat;
		if (totalInFlight > this._state.remoteConfig.maxHtlcValueInFlightMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Max HTLC value in flight exceeded'
				}
			];
		}

		// Check we have enough balance (including reserve the remote requires us
		// to maintain, plus the funder's commitment fee — BOLT 2). Delegated to
		// getSpendableOutboundMsat so the same ceiling that gates an add here is
		// the one accounting/routing surfaces report, and so a pending splice's
		// lower-balance commitment (when the gates allow adds mid-splice) is
		// automatically respected.
		if (amountMsat > this.getSpendableOutboundMsat()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Insufficient balance for HTLC'
				}
			];
		}

		// Cap total dust-HTLC exposure (BOLT 2 recommendation): dust HTLCs are
		// trimmed from the commitment, so at force-close their full value goes
		// to miner fees. Bound the worst case.
		if (
			this._isDustHtlc(amountMsat) &&
			this._dustExposureMsat() + amountMsat >
				Channel.MAX_DUST_HTLC_EXPOSURE_MSAT
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Dust HTLC exposure limit exceeded'
				}
			];
		}

		const htlcId = this._state.localHtlcCounter++;

		const entry: IHtlcEntry = {
			id: htlcId,
			amountMsat,
			paymentHash,
			cltvExpiry,
			onionRoutingPacket,
			direction: HtlcDirection.OFFERED,
			state: HtlcState.PENDING,
			// Two-phase: the peer incorporates this add into its signatures over
			// OUR commitment only after revoking a commitment of ours covering it.
			addRemoteCommitted: false,
			...(blindingPoint ? { blindingPoint } : {})
		};

		this._state.htlcs.set(`offered-${htlcId}`, entry);

		// Deduct from local balance provisionally
		this._state.localBalanceMsat -= amountMsat;

		const msg: IUpdateAddHtlcMessage = {
			channelId: this._state.channelId!,
			id: htlcId,
			amountMsat,
			paymentHash,
			cltvExpiry,
			onionRoutingPacket,
			...(blindingPoint ? { blindingPoint } : {})
		};

		// We added an offered HTLC — we owe the remote a commitment_signed.
		this._state.needsCommitment = true;

		const payload = encodeUpdateAddHtlcMessage(msg);
		// BOLT 2 reestablish: queue the raw update until the peer's
		// revoke_and_ack acknowledges it — a reconnect must retransmit it.
		this._queuePendingLocalUpdate(MessageType.UPDATE_ADD_HTLC, payload);

		// Persist before the add reaches the peer: the queued retransmission
		// entry, the HTLC itself and (for a forward) the caller's staged
		// linkage all commit together, so no crash can leave an HTLC the peer
		// holds and we have no record of.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.UPDATE_ADD_HTLC, payload)
		];
	}

	/**
	 * Handle update_add_htlc from remote (received HTLC).
	 */
	handleUpdateAddHtlc(msg: IUpdateAddHtlcMessage): ChannelAction[] {
		// An add that crossed OUR OWN shutdown on the wire. BOLT 2 forbids an add
		// only AFTER the peer has received our shutdown, and until it sends its own
		// we have no evidence it has: its add may have left before ours arrived.
		// Such an add MUST be recorded. Dropping it does not spare the channel, it
		// only mislabels its death: the peer's covering commitment_signed is then
		// verified against a commitment that lacks the HTLC, fails, and
		// handleCommitmentSigned fails the channel over an "invalid signature"
		// that was never invalid. handleCommitmentSigned accepts SHUTTING_DOWN for
		// exactly this reason, and BOLT 2 requires the shutdown to wait for
		// in-flight HTLCs to resolve before closing_signed.
		const crossedOurShutdown =
			this._state.state === ChannelState.SHUTTING_DOWN &&
			this._state.remoteShutdownScript === null;

		if (
			this._state.state !== ChannelState.NORMAL &&
			!this.canUpdateHtlcsDuringSplice() &&
			!crossedOurShutdown
		) {
			// Every OTHER refusal in this handler is wire-visible (issue 404). This
			// one stays LOCAL even once the peer has provably bound itself, and that
			// is a decision rather than the carve-out it looks like:
			//
			//  - Nothing cascades from it. In NEGOTIATING_CLOSING, CLOSED or
			//    SPLICING the covering commitment_signed is refused by
			//    handleCommitmentSigned's own state gate, or routed to the splice
			//    batch path, so the add stalls and nothing is force closed. That is
			//    the opposite of the SHUTTING_DOWN case carved out above, where the
			//    commitment IS verified and the channel dies on a signature that was
			//    never wrong. Only that case needed fixing.
			//  - Wire-failing here would force close CONFORMANT peers.
			//    handleReestablish replays every queued update_add_htlc after a
			//    reconnect (BOLT 2: "Retransmit un-acked update messages"), and
			//    remoteShutdownScript is persisted, so a peer retransmitting an
			//    unrevoked add into a shutting-down channel is doing exactly what
			//    the spec tells it to. Mid-splice the same: this implementation
			//    parks TAPROOT channels in quiescence for the whole pending-lock
			//    window (canUpdateHtlcsDuringSplice), longer than the splicing spec
			//    requires, so a conformant taproot peer resuming updates there would
			//    be condemned for our own conservatism.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_add_htlc',
					cleanup: 'none'
				}
			];
		}

		// Dedup check (BOLT 2 reestablish): a replay of an add we already hold
		// is a no-op — but ONLY if it is byte-identical. markForReestablish
		// reverses uncommitted adds, so any surviving entry was committed and
		// its id can never be legitimately reused: an id collision with
		// different contents is a protocol violation that would desync the
		// commitment if swallowed, so fail the channel instead.
		const existing = this._state.htlcs.get(`received-${msg.id}`);
		if (existing) {
			if (
				existing.amountMsat === msg.amountMsat &&
				existing.paymentHash.equals(msg.paymentHash) &&
				existing.cltvExpiry === msg.cltvExpiry &&
				existing.onionRoutingPacket.equals(msg.onionRoutingPacket)
			) {
				return [];
			}
			return this._failChannelWithWireError(
				`update_add_htlc reuses id ${msg.id} with different contents`
			);
		}

		// Reject during quiescence only once the PEER has sent stfu. From its own
		// stfu the peer is bound by BOLT 2's "MUST NOT send an update message
		// after stfu", and that stfu preceded this add on the same ordered
		// stream, so no race can produce it: the refusal is provable divergence
		// and the peer must hear it (issue 404).
		//
		// While only WE have sent stfu the peer owes nothing yet. Its obligation
		// starts at ITS receipt of ours, which we cannot observe, and BOLT 2
		// requires that window to exist: a peer holding pending updates has to
		// drain them before it can "reply with stfu once it can do so". So a
		// crossing add is conformant and is ACCEPTED here (issue 411); the node
		// parks its disposition until quiescence ends, and the manager's
		// quiescence watchdog enforces BOLT 2's 60-second disconnect if the
		// session stalls with HTLCs pending.
		// Reached from NORMAL (a quiescence handshake that has not moved the
		// channel state yet); the lifecycle guard above already answered the same
		// question for a channel that has moved.
		if (this._quiescence.peerHasSentStfu()) {
			return this._failChannelWithWireError('update_add_htlc after your stfu');
		}

		// Validate inbound HTLC per BOLT 2
		if (msg.amountMsat <= 0n) {
			// BOLT 2 MUST fail: a zero-amount add can never enter our commitment.
			return this._failChannelWithWireError(
				'HTLC amount must be greater than 0'
			);
		}

		if (msg.amountMsat < this._state.localConfig.htlcMinimumMsat) {
			// BOLT 2 MUST fail: below the htlc_minimum_msat we advertised.
			return this._failChannelWithWireError('HTLC amount below our minimum');
		}

		const pendingReceived = this.countPendingHtlcs(HtlcDirection.RECEIVED);
		if (pendingReceived >= this._state.localConfig.maxAcceptedHtlcs) {
			// BOLT 2 MUST fail: over the max_accepted_htlcs we advertised.
			return this._failChannelWithWireError(
				'Max inbound pending HTLCs exceeded'
			);
		}

		const totalReceivedInFlight =
			this.totalInFlightMsat(HtlcDirection.RECEIVED) + msg.amountMsat;
		if (
			totalReceivedInFlight > this._state.localConfig.maxHtlcValueInFlightMsat
		) {
			// BOLT 2 MUST fail: over the max_htlc_value_in_flight_msat we advertised.
			return this._failChannelWithWireError(
				'Max inbound HTLC value in flight exceeded'
			);
		}

		// Enforce the channel reserve (and, if the remote is the funder, the
		// commitment fee) on the SENDER before provisionally debiting their
		// balance. The outbound addHtlc path checks this for us; the inbound path
		// previously debited remoteBalanceMsat unconditionally, so an over-large
		// HTLC could drive it negative and corrupt commitment accounting / violate
		// the reserve (BOLT 2). The reserve the remote must keep is the one WE
		// required of them (localConfig.channelReserveSatoshis).
		const remoteReserveMsat =
			this._state.localConfig.channelReserveSatoshis * 1000n;
		let remoteRequiredMsat = remoteReserveMsat;
		if (this._state.role === ChannelRole.ACCEPTOR) {
			// We are the acceptor, so the remote is the funder and must also cover
			// the commitment fee above its reserve — priced at the LIVE commitment
			// feerate, the rate real commitments are built at. Pricing it at the
			// static open-time localConfig.feeratePerKw made this check disagree
			// with the sender's own live-rate arithmetic whenever the two rates
			// drifted apart, and a boundary HTLC then failed the channel over a
			// sats-scale formula difference between two honest nodes (#193).
			// The fee plus, on anchor channels, the two 330-sat anchor outputs
			// the builder deducts from the funder separately: one expression, so
			// the base weight this channel type prices at and the anchor add can
			// never be applied apart (#403).
			remoteRequiredMsat +=
				funderCommitmentCostSats(
					Math.max(
						getLocalCommitmentFeeRate(this._state),
						getRemoteCommitmentFeeRate(this._state)
					),
					this._countActiveHtlcs() + 1,
					this._state.channelType
				) * 1000n;
		}
		if (this._state.remoteBalanceMsat - msg.amountMsat < remoteRequiredMsat) {
			// BOLT 2 MUST fail: an add the sender cannot afford above its reserve can
			// never enter our commitment, so its log now holds an entry ours never
			// will. Wire error (issue 404): the silent refusal this replaced let the
			// peer's next commitment_signed cover state we do not hold, and the
			// channel force closed a round later blamed on an invalid signature.
			return this._failChannelWithWireError(
				'Remote cannot afford HTLC above channel reserve'
			);
		}

		// The dust-exposure ceiling is deliberately NOT enforced here. BOLT 2
		// ("Bounding exposure to trimmed in-flight HTLCs"): the receiver SHOULD
		// fail such an HTLC once it's committed, not refuse the add. The
		// classification is made NOW and stamped on the entry (see
		// dustExposureFailback below): dispatch-time recomputation is
		// order-dependent once batched siblings start settling, and a restart
		// replay must answer identically.
		const dustExposureFailback =
			this._isDustHtlc(msg.amountMsat) &&
			this._dustExposureMsat() + msg.amountMsat >
				Channel.MAX_DUST_HTLC_EXPOSURE_MSAT;

		// BOLT 2: cltv_expiry >= 500000000 is a unix timestamp, not a block
		// height — always invalid, independent of whether we know the current
		// block height.
		if (msg.cltvExpiry >= 500_000_000) {
			return this._failChannelWithWireError(
				`HTLC cltv_expiry ${msg.cltvExpiry} is not a block height (>= 500000000)`
			);
		}

		// CLTV validation
		if (this._currentBlockHeight > 0) {
			if (msg.cltvExpiry <= this._currentBlockHeight) {
				// The one arm that turns on state the peer cannot see, our own
				// _currentBlockHeight. A skew large enough to reach here past the
				// sender's cltv_expiry_delta means our chain view is broken rather than
				// that the peer raced us, and the add cannot enter our commitment
				// either way.
				return this._failChannelWithWireError('HTLC CLTV already expired');
			}
			// The far-future horizon (MAX_HTLC_CLTV_EXPIRY_DELTA) is OUR policy,
			// not a BOLT 2 MUST: the node admits the add and fails it back with
			// expiry_too_far once committed (issue 410).
		}

		const entry: IHtlcEntry = {
			id: msg.id,
			amountMsat: msg.amountMsat,
			paymentHash: msg.paymentHash,
			cltvExpiry: msg.cltvExpiry,
			onionRoutingPacket: msg.onionRoutingPacket,
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.PENDING,
			...(msg.blindingPoint ? { blindingPoint: msg.blindingPoint } : {}),
			...(dustExposureFailback ? { dustExposureFailback: true } : {})
		};

		// The reserve check above is measured against the reserve WE enforce,
		// which on an asymmetric-dust channel can sit below our own dust limit.
		// An add that trims on our side then takes the peer's balance under it
		// too, and the commitment we hold ends up with nothing to broadcast
		// (issue #386). Asked of a candidate rather than of live state, so a
		// refusal leaves nothing behind.
		const wouldEmpty = this._localCommitmentEmptyRefusal({
			remoteBalanceMsat: this._state.remoteBalanceMsat - msg.amountMsat,
			addedHtlc: { key: `received-${msg.id}`, entry }
		});
		if (wouldEmpty) {
			return this._failChannelWithWireError(wouldEmpty);
		}

		this._state.htlcs.set(`received-${msg.id}`, entry);
		// Two-phase: the peer's add enters commitments WE sign only after we
		// revoke for the peer's covering commitment_signed (the peer builds its
		// own local commitment WITHOUT the add until it holds our
		// revoke_and_ack). handleCommitmentSigned flips this and marks the
		// commitment we then owe. Setting needsCommitment here (the previous
		// behavior) let unrelated triggers sign the peer's own add into its
		// commitment prematurely — "Bad commit_sig" at the peer.
		entry.addLocallyRevoked = false;

		// Deduct from remote balance provisionally
		this._state.remoteBalanceMsat -= msg.amountMsat;

		// Note: HTLC_FORWARDED is NOT emitted here — per BOLT 2, HTLCs should
		// only be processed after commitment_signed is verified and revoke_and_ack
		// is sent. The event is emitted from handleCommitmentSigned instead.
		return [];
	}

	/**
	 * BOLT 2 send-side guard: a received HTLC we have already settled must not be
	 * settled a second time. The peer removes an HTLC from its update log as soon
	 * as it accepts our update_fulfill/update_fail, so a repeat names an id the
	 * peer no longer holds, and a peer answers that by failing the channel.
	 *
	 * A repeat of the SAME resolution is a no-op, mirroring the receive-side
	 * dedup in handleUpdateFulfillHtlc: that is the harmless shape of this
	 * mistake (an honest retransmission), and callers reasonably fire twice.
	 *
	 * The CROSS transition is an error rather than a no-op, because it moves
	 * money. Failing an HTLC we already fulfilled would overwrite entry.state and
	 * send the value to remoteBalanceMsat on the next revoke_and_ack, giving away
	 * value whose preimage we have already revealed. Fulfilling one we already
	 * failed reveals a preimage for value we have told the peer to take back.
	 *
	 * Returns the actions the caller should return, or null to proceed.
	 */
	private _guardRepeatSettle(
		entry: IHtlcEntry,
		htlcId: bigint,
		intent: HtlcState.FULFILLED | HtlcState.FAILED
	): ChannelAction[] | null {
		if (entry.state === intent) {
			return [];
		}
		if (
			entry.state === HtlcState.FULFILLED ||
			entry.state === HtlcState.FAILED
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `HTLC ${htlcId} already ${entry.state.toLowerCase()}`
				}
			];
		}
		return null;
	}

	/**
	 * Fulfill a received HTLC with a preimage.
	 */
	/**
	 * Whether fulfillHtlc would currently accept this received HTLC: the
	 * channel can carry updates and the entry is live (not already settled).
	 * Callers that must pair irreversible bookkeeping with the fulfill (the
	 * forwarder's linkage delete) check this first, because a refused fulfill
	 * must not consume the bookkeeping a later retry needs. Mirrors the
	 * guards of fulfillHtlc below; keep the two in step.
	 */
	canFulfillHtlc(htlcId: bigint): boolean {
		if (!this.canSettleHtlcs()) return false;
		const entry = this._state.htlcs.get(`received-${htlcId}`);
		if (!entry) return false;
		return (
			entry.state !== HtlcState.FULFILLED && entry.state !== HtlcState.FAILED
		);
	}

	/**
	 * Whether failHtlc would currently accept this received HTLC. Same
	 * contract and purpose as canFulfillHtlc above: callers that pair
	 * irreversible bookkeeping with the fail check this first, because a
	 * refused fail must not consume the bookkeeping a later retry needs.
	 */
	canFailHtlc(htlcId: bigint): boolean {
		return this.canFulfillHtlc(htlcId);
	}

	fulfillHtlc(htlcId: bigint, paymentPreimage: Buffer): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fulfill HTLC: wrong state'
				}
			];
		}
		// BOLT 2 quiescence: "MUST NOT send an update message after stfu". The
		// manager defers settles on a quiescing channel before reaching here;
		// this guard covers callers driving the Channel directly.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fulfill HTLC: channel is quiescing'
				}
			];
		}

		const key = `received-${htlcId}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${htlcId} not found` }
			];
		}

		// Verify preimage. Checked before the repeat guard so a caller passing a
		// preimage that does not hash to this HTLC is told so either way, rather
		// than getting a silent no-op because the entry happens to be settled.
		const hash = crypto.createHash('sha256').update(paymentPreimage).digest();
		if (!hash.equals(entry.paymentHash)) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Invalid preimage for HTLC' }
			];
		}

		const repeat = this._guardRepeatSettle(entry, htlcId, HtlcState.FULFILLED);
		if (repeat) {
			return repeat;
		}

		entry.state = HtlcState.FULFILLED;
		// Two-phase: the peer's signatures still include this HTLC until it
		// revokes for our removal — buildLocalCommitment keeps it present.
		entry.removalRemoteCommitted = false;

		// Note: balance is NOT updated here. The credit to localBalanceMsat
		// happens when the remote sends revoke_and_ack, confirming the
		// commitment that removes this HTLC (BOLT 2 state machine).

		// We fulfilled a received HTLC — we owe the remote a commitment_signed
		// to commit the removal.
		this._state.needsCommitment = true;

		const msg: IUpdateFulfillHtlcMessage = {
			channelId: this._state.channelId!,
			id: htlcId,
			paymentPreimage
		};

		const payload = encodeUpdateFulfillHtlcMessage(msg);
		// BOLT 2 reestablish: a lost update_fulfill strands the HTLC (and the
		// revealed preimage) — queue it for retransmission until acked.
		this._queuePendingLocalUpdate(MessageType.UPDATE_FULFILL_HTLC, payload);

		// Persist before the preimage reaches the peer. Previously this
		// returned the send alone and durability of the preimage rested on
		// every caller having saved it first; with PERSIST_STATE here, the
		// caller's staged preimage mutation and this message commit as one
		// unit (docs/RECOVERY-PROTOCOL.md 5.1).
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.UPDATE_FULFILL_HTLC, payload)
		];
	}

	/**
	 * Handle update_fulfill_htlc from remote.
	 */
	handleUpdateFulfillHtlc(msg: IUpdateFulfillHtlcMessage): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_fulfill_htlc'
				}
			];
		}

		const key = `offered-${msg.id}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			// A bare local ERROR, deliberately (issue 409 carve-out). BOLT 2
			// reads this as a MUST-fail, but a legal crossing reaches it: a peer
			// that crashed after completing the removal round and restored a
			// lagging snapshot (the issue 295/297 window this codebase embraces)
			// replays its WHOLE pending-update queue on reestablish, and our own
			// handleReestablish does exactly that, unconditionally. The replayed
			// fulfill/fail then lands on an entry handleRevokeAndAck already
			// deleted. A replay that finds the entry takes the repeat branch
			// below; this arm is the same family one persist further along, and
			// a guard that kills a channel must carry no known false positives.
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// Verify the revealed preimage actually hashes to this HTLC's
		// payment_hash before crediting the counterparty. Without this a peer
		// could fulfill with a bogus preimage and, on the next revoke_and_ack,
		// move the HTLC value into their balance with no valid proof revealed:
		// direct theft of every HTLC we offer. Mirrors the receive-side check in
		// fulfillHtlc(). Checked before the repeat branch below so a replay
		// carrying a bogus preimage is rejected, not silently tolerated.
		const fulfillHash = crypto
			.createHash('sha256')
			.update(msg.paymentPreimage)
			.digest();
		if (!fulfillHash.equals(entry.paymentHash)) {
			// An attempted theft answered with silence was the worst of the bare
			// arms (issue 409): the peer kept the bogus fulfill in its book and
			// the channel died a round later on a signature mismatch.
			return this._failChannelWithWireError(
				'Invalid preimage for offered HTLC'
			);
		}

		// A reestablish replay of a fulfill we already processed (BOLT 2 update
		// retransmission) changes no channel state, but it must still re-emit
		// HTLC_FULFILLED. The channel state carrying FULFILLED can reach disk
		// in a commit that precedes the node-level preimage and forward
		// bookkeeping (the quorum pipeline persists deferred snapshots), and a
		// process killed in that window restarts knowing the fulfill happened
		// while holding no preimage at all. The peer's retransmission is then
		// the only remaining source, so swallowing it here would strand the
		// upstream leg of a forward forever (issue 295). Every listener on the
		// resulting event is repeat-tolerant.
		if (entry.state === HtlcState.FULFILLED) {
			return [
				{
					type: ChannelActionType.HTLC_FULFILLED,
					htlcId: msg.id,
					paymentPreimage: msg.paymentPreimage
				}
			];
		}

		entry.state = HtlcState.FULFILLED;
		// Two-phase: finalize the balance movement (and delete the entry) only
		// once the peer has revoked for OUR commitment covering this removal.
		entry.removalRemoteCommitted = false;
		// And the peer's removal enters commitments WE sign only after we
		// revoke for its covering commitment_signed — until then the peer's own
		// local commitment still contains the HTLC, and a premature
		// removal-applied signature is "Bad commit_sig" at the peer (observed
		// live vs CLN). handleCommitmentSigned flips this and sets
		// needsCommitment for the removal-ack round.
		entry.removalLocallyRevoked = false;

		// Note: balance is NOT updated here. The credit to remoteBalanceMsat
		// happens when the commitment exchange confirms via revoke_and_ack.

		return [
			{
				type: ChannelActionType.HTLC_FULFILLED,
				htlcId: msg.id,
				paymentPreimage: msg.paymentPreimage
			}
		];
	}

	/**
	 * Fail a received HTLC. HTLC ids are per-direction, so the direction MUST be
	 * validated: an offered HTLC we sent shares its numeric id space with the
	 * received HTLCs, and failing by numeric id alone would cancel an unrelated
	 * received HTLC. Only a received HTLC (one the peer offered us) can be failed
	 * off-chain via update_fail_htlc; an offered HTLC is resolved by the peer or
	 * on-chain, never by us. Direction defaults to RECEIVED so existing callers
	 * (all of which fail inbound HTLCs) are unchanged.
	 */
	failHtlc(
		htlcId: bigint,
		reason: Buffer,
		direction: HtlcDirection = HtlcDirection.RECEIVED
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: wrong state'
				}
			];
		}

		// BOLT 2 quiescence: "MUST NOT send an update message after stfu". The
		// manager defers settles on a quiescing channel before reaching here;
		// this guard covers callers driving the Channel directly.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: channel is quiescing'
				}
			];
		}

		// BOLT 2: update_fail_htlc removes an HTLC the PEER offered us. Refuse to
		// fail one we offered rather than fall through to the received-keyed lookup
		// and corrupt the same-id inbound HTLC.
		if (direction !== HtlcDirection.RECEIVED) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot fail offered HTLC ${htlcId} off-chain`
				}
			];
		}

		const key = `received-${htlcId}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${htlcId} not found` }
			];
		}

		const repeat = this._guardRepeatSettle(entry, htlcId, HtlcState.FAILED);
		if (repeat) {
			return repeat;
		}

		entry.state = HtlcState.FAILED;
		// Two-phase: the peer's signatures still include this HTLC until it
		// revokes for our removal — buildLocalCommitment keeps it present.
		entry.removalRemoteCommitted = false;

		// Note: balance is NOT refunded here. The refund to remoteBalanceMsat
		// happens when the commitment exchange confirms the removal (BOLT 2).

		// We failed a received HTLC — we owe the remote a commitment_signed to
		// commit the removal.
		this._state.needsCommitment = true;

		const msg: IUpdateFailHtlcMessage = {
			channelId: this._state.channelId!,
			id: htlcId,
			reason
		};

		const payload = encodeUpdateFailHtlcMessage(msg);
		// BOLT 2 reestablish: queue for retransmission until acked.
		this._queuePendingLocalUpdate(MessageType.UPDATE_FAIL_HTLC, payload);

		// Persist the queued retransmission entry before the fail goes out.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.UPDATE_FAIL_HTLC, payload)
		];
	}

	/**
	 * Fail a received HTLC with update_fail_malformed_htlc (BOLT 2). Used when
	 * the onion itself is unparseable, and by BOLT 4 route blinding: a blinded
	 * hop that got its blinding point in update_add_htlc MUST fail with
	 * invalid_onion_blinding via this message. Same state machine as failHtlc;
	 * the failure_code MUST have BADONION set.
	 */
	failMalformedHtlc(
		htlcId: bigint,
		sha256OfOnion: Buffer,
		failureCode: number
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: wrong state'
				}
			];
		}

		// BOLT 2 quiescence: "MUST NOT send an update message after stfu". The
		// manager defers settles on a quiescing channel before reaching here;
		// this guard covers callers driving the Channel directly.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: channel is quiescing'
				}
			];
		}

		if ((failureCode & 0x8000) === 0) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `update_fail_malformed_htlc failure_code ${failureCode} lacks BADONION`
				}
			];
		}

		const key = `received-${htlcId}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${htlcId} not found` }
			];
		}

		const repeat = this._guardRepeatSettle(entry, htlcId, HtlcState.FAILED);
		if (repeat) {
			return repeat;
		}

		entry.state = HtlcState.FAILED;
		// Two-phase removal, exactly as failHtlc.
		entry.removalRemoteCommitted = false;
		this._state.needsCommitment = true;

		const msg: IUpdateFailMalformedHtlcMessage = {
			channelId: this._state.channelId!,
			id: htlcId,
			sha256OfOnion,
			failureCode
		};

		const payload = encodeUpdateFailMalformedHtlcMessage(msg);
		// BOLT 2 reestablish: queue for retransmission until acked.
		this._queuePendingLocalUpdate(
			MessageType.UPDATE_FAIL_MALFORMED_HTLC,
			payload
		);

		// Persist the queued retransmission entry before the fail goes out.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.UPDATE_FAIL_MALFORMED_HTLC, payload)
		];
	}

	/**
	 * Handle update_fail_htlc from remote.
	 */
	handleUpdateFailHtlc(msg: IUpdateFailHtlcMessage): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_fail_htlc'
				}
			];
		}

		const key = `offered-${msg.id}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			// Deliberately bare: see the crash-replay carve-out argued at
			// handleUpdateFulfillHtlc's not-found arm.
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// A reestablish replay of a fail we already processed (BOLT 2 update
		// retransmission) changes no channel state, but it must still re-emit
		// HTLC_FAILED: the channel state carrying FAILED can reach disk in a
		// commit that precedes the node-level upstream fail (the quorum
		// pipeline persists deferred snapshots, the same window as issue 295's
		// fulfill side), and swallowing the replay leaves the inbound leg
		// stalled until the CLTV sweeper. Every listener on the resulting
		// event is repeat-tolerant (issue 297).
		if (entry.state === HtlcState.FAILED) {
			return [
				{
					type: ChannelActionType.HTLC_FAILED,
					htlcId: msg.id,
					reason: msg.reason
				}
			];
		}

		entry.state = HtlcState.FAILED;
		// Two-phase: finalize the refund (and delete the entry) only once the
		// peer has revoked for OUR commitment covering this removal.
		entry.removalRemoteCommitted = false;
		// The peer's removal enters commitments WE sign only after we revoke
		// for its covering commitment_signed (see handleUpdateFulfillHtlc).
		entry.removalLocallyRevoked = false;

		// Note: balance is NOT refunded here. The refund to localBalanceMsat
		// happens when the commitment exchange confirms via revoke_and_ack.

		return [
			{
				type: ChannelActionType.HTLC_FAILED,
				htlcId: msg.id,
				reason: msg.reason
			}
		];
	}

	/**
	 * Handle update_fail_malformed_htlc from remote (BOLT 2).
	 * The failure_code MUST have the BADONION bit (0x8000) set.
	 */
	handleUpdateFailMalformedHtlc(
		msg: IUpdateFailMalformedHtlcMessage
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.canUpdateHtlcsDuringSplice()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_fail_malformed_htlc'
				}
			];
		}

		// BOLT 2: failure_code MUST have BADONION (0x8000) bit set. A pure check
		// of the message bytes, so nothing in flight can excuse it.
		if ((msg.failureCode & 0x8000) === 0) {
			return this._failChannelWithWireError(
				'update_fail_malformed_htlc: failure_code missing BADONION bit'
			);
		}

		const key = `offered-${msg.id}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			// Deliberately bare: see the crash-replay carve-out argued at
			// handleUpdateFulfillHtlc's not-found arm.
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// A replay of a malformed-fail we already processed re-emits the event
		// for the same reason as handleUpdateFailHtlc above (issue 297); the
		// synthetic reason is rebuilt identically from the failure code.
		if (entry.state === HtlcState.FAILED) {
			const replayReason = Buffer.alloc(4);
			replayReason.writeUInt16BE(msg.failureCode, 0);
			replayReason.writeUInt16BE(0, 2);
			return [
				{
					type: ChannelActionType.HTLC_FAILED,
					htlcId: msg.id,
					reason: replayReason
				}
			];
		}

		// A malformed-HTLC removal follows the SAME two-phase settlement as a plain
		// update_fail_htlc (mirror handleUpdateFailHtlc). Setting FAILED and
		// crediting localBalanceMsat here while leaving the phase flags undefined
		// made the revoke settlement loop credit the same HTLC a SECOND time (the
		// loop only skips entries whose removalRemoteCommitted === false): a double
		// credit that inflated our balance and desynced the commitment.
		entry.state = HtlcState.FAILED;
		entry.removalRemoteCommitted = false;
		entry.removalLocallyRevoked = false;

		// Note: balance is NOT refunded here. The refund to localBalanceMsat
		// happens when the commitment exchange confirms via revoke_and_ack.

		// Build a synthetic reason buffer with the failure code
		const reason = Buffer.alloc(4);
		reason.writeUInt16BE(msg.failureCode, 0);
		reason.writeUInt16BE(0, 2); // empty data length

		return [
			{
				type: ChannelActionType.HTLC_FAILED,
				htlcId: msg.id,
				reason
			}
		];
	}

	/**
	 * BOLT 2 reestablish: remember a raw outgoing update message until the
	 * peer's revoke_and_ack acknowledges the commitment that contains it. On
	 * reconnection the peer may have lost it (uncommitted updates are
	 * forgotten across a disconnect, and a restarted peer restores a state
	 * that may predate it), so handleReestablish retransmits the queue BEFORE
	 * any retransmitted commitment_signed. Receivers treat replays
	 * idempotently (duplicate add ids are ignored; a fulfill/fail of an
	 * already fulfilled/failed HTLC is a no-op).
	 */
	private _queuePendingLocalUpdate(type: MessageType, payload: Buffer): void {
		this._state.pendingLocalUpdates.push({
			type,
			payload: Buffer.from(payload)
		});
	}

	/**
	 * Record which HTLCs are present in a given remote commitment so the penalty
	 * path can reconstruct their outputs after they settle. Only HTLCs that
	 * actually appear in the commitment (PENDING/COMMITTED) are captured.
	 */
	private _snapshotRemoteCommitmentHtlcs(commitmentNumber: bigint): void {
		const entries: IHtlcSnapshotEntry[] = [];
		for (const htlc of this._state.htlcs.values()) {
			if (
				htlc.state === HtlcState.PENDING ||
				htlc.state === HtlcState.COMMITTED ||
				htlc.state === HtlcState.FULFILLED ||
				htlc.state === HtlcState.FAILED
			) {
				entries.push({
					paymentHash: Buffer.from(htlc.paymentHash),
					amountMsat: htlc.amountMsat,
					cltvExpiry: htlc.cltvExpiry,
					direction: htlc.direction
				});
			}
		}
		if (!this._state.revokedHtlcSnapshots) {
			this._state.revokedHtlcSnapshots = new Map();
		}
		this._state.revokedHtlcSnapshots.set(commitmentNumber.toString(), entries);
	}

	/**
	 * Cache the remote commitment tx we just signed, keyed by its per-commitment
	 * point, mirroring the manager's build (remoteNextPerCommitmentPoint, number
	 * +1). Taproot commitments are cached too: they feed the version-1 (schnorr)
	 * justice kit. Never throws: a cache miss only forfeits a pre-emptive tower
	 * ship, it must not break commitment signing.
	 */
	private _cacheRemoteCommitmentForWatchtower(): void {
		try {
			if (!this._state.remoteBasepoints || !this._state.fundingTxid) return;
			const point =
				this._state.remoteNextPerCommitmentPoint ||
				this._state.remoteCurrentPerCommitmentPoint;
			if (!point) return;
			const built = buildRemoteCommitment(
				this._state,
				point,
				this._state.remoteCommitmentNumber + 1n
			);
			this._remoteCommitmentTxCache.set(
				point.toString('hex'),
				built.result.tx.toBuffer().toString('hex')
			);
			// Bound the cache: only unrevoked states matter and there are few.
			while (
				this._remoteCommitmentTxCache.size > Channel.REVOKED_TX_CACHE_MAX
			) {
				const oldest = this._remoteCommitmentTxCache.keys().next().value;
				if (oldest === undefined) break;
				this._remoteCommitmentTxCache.delete(oldest);
			}
		} catch {
			// Best-effort cache; ignore.
		}
	}

	/**
	 * Given a per-commitment secret the peer just revealed, return (and forget)
	 * the revoked remote commitment tx we cached for that state, or null if we
	 * never signed it (e.g. the initial funding commitment).
	 */
	takeRevokedCommitmentTx(perCommitmentSecret: Buffer): Buffer | null {
		const pointHex =
			perCommitmentPointFromSecret(perCommitmentSecret).toString('hex');
		const txHex = this._remoteCommitmentTxCache.get(pointHex);
		if (!txHex) return null;
		this._remoteCommitmentTxCache.delete(pointHex);
		return Buffer.from(txHex, 'hex');
	}

	/**
	 * Sign and send commitment_signed.
	 * The caller provides the signature and HTLC signatures (from commitment-builder).
	 */
	signCommitment(
		signature: Buffer,
		htlcSignatures: Buffer[],
		partialSignatureWithNonce?: Buffer,
		spliceBatch?: {
			/** Signature over the peer's commitment for the PENDING splice funding. */
			spliceSignature: Buffer;
			spliceHtlcSignatures: Buffer[];
		}
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.isSplicePendingLock()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot sign commitment: wrong state'
				}
			];
		}

		// While a fully-signed splice awaits its lock, a commitment update signs
		// one commitment per active funding output, sent as a start_batch batch.
		if (this.isSplicePendingLock() && !spliceBatch) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot sign commitment: pending splice requires a commitment batch'
				}
			];
		}

		// option_taproot: the commitment is co-signed with a MuSig2 partial carried
		// in partial_signature_with_nonce; the fixed 64-byte signature field is zero.
		const taproot = isTaprootChannel(this._state.channelType);
		if (
			taproot &&
			(!partialSignatureWithNonce || partialSignatureWithNonce.length !== 98)
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Taproot commitment_signed requires a partial_signature_with_nonce'
				}
			];
		}

		const msg: ICommitmentSignedMessage = {
			channelId: this._state.channelId!,
			signature: taproot ? Buffer.alloc(64) : signature,
			htlcSignatures,
			partialSignatureWithNonce: taproot ? partialSignatureWithNonce : undefined
		};
		if (spliceBatch && this._state.fundingTxid) {
			// Batched commitments are routed by their funding_txid TLV.
			msg.fundingTxid = Buffer.from(this._state.fundingTxid);
		}

		// Cache for retransmission on reestablish. For taproot we cache the
		// 98-byte partial_signature_with_nonce that actually went on the wire so
		// a reconnect replays the identical message (the all-zero `signature`
		// field carries no signing material for taproot).
		this._state.lastSentCommitmentSigned = Buffer.from(signature);
		this._state.lastSentPartialSignatureWithNonce =
			taproot && partialSignatureWithNonce
				? Buffer.from(partialSignatureWithNonce)
				: null;
		this._state.lastSentHtlcSignatures = htlcSignatures.map((s) =>
			Buffer.from(s)
		);
		// Reestablish ordering (BOLT 2): commitment_signed is now the most
		// recently sent of {commitment_signed, revoke_and_ack}.
		this._state.lastSentWasRevoke = false;

		// Snapshot the HTLCs committed in the remote commitment we just signed,
		// keyed by its number, so a later penalty can sweep these outputs even
		// after they settle and leave `htlcs` (H2 — revoked-HTLC justice).
		this._snapshotRemoteCommitmentHtlcs(this._state.remoteCommitmentNumber);

		// Watchtower: cache the remote commitment tx we just committed the peer to,
		// keyed by its per-commitment point, for pre-emptive justice on breach.
		this._cacheRemoteCommitmentForWatchtower();

		// A staged update_fee that is signable here (opener always; acceptor
		// once the fee round reached it — see getRemoteCommitmentFeeRate) is
		// baked into this signature: the peer's revoke_and_ack for it finalizes
		// the fee round and promotes the staged rate to the committed config.
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			(this._state.role === ChannelRole.OPENER ||
				this._state.pendingFeerateSignable === true)
		) {
			this._state.pendingFeerateCommitted = true;
		}

		// update_blockheight, same machine: a signable staged height is baked
		// into this signature; the answering revoke_and_ack promotes it.
		if (
			this._state.pendingLeaseBlockheight !== undefined &&
			this._state.pendingLeaseBlockheightSignable === true
		) {
			this._state.pendingLeaseBlockheightCommitted = true;
		}

		// Two-phase updates: stamp every entry whose phase THIS signature
		// advances — the peer's answering revoke_and_ack promotes them
		// (addRemoteCommitted / removalRemoteCommitted) in handleRevokeAndAck.
		// A removal is only in this signature once it is signable: our own
		// removals always are; a peer removal only after we revoked for it
		// (removalLocallyRevoked — buildRemoteCommitment keeps the HTLC present
		// until then).
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.addRemoteCommitted === false &&
				(entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED)
			) {
				entry.commitCoverPending = true;
			}
			if (
				entry.removalRemoteCommitted === false &&
				entry.removalLocallyRevoked !== false &&
				(entry.state === HtlcState.FULFILLED ||
					entry.state === HtlcState.FAILED)
			) {
				entry.commitCoverPending = true;
			}
		}

		// Materialize the revocation counter (legacy states lack it) BEFORE
		// advancing the sign counter, so the two can diverge by exactly the one
		// commitment this signature puts in flight.
		this._state.remoteRevocationNumber = this._remoteRevocationCount();

		// Advance remote commitment number
		this._state.remoteCommitmentNumber++;

		// We have now committed all pending updates to the remote — clear the flag
		// so we don't re-send commitment_signed for an unchanged state.
		this._state.needsCommitment = false;

		// Everything queued so far is covered by this signature; the peer's
		// revoke_and_ack will acknowledge exactly this many updates.
		this._state.pendingLocalUpdatesSignedCount =
			this._state.pendingLocalUpdates.length;

		// Move pending HTLCs to committed
		for (const entry of this._state.htlcs.values()) {
			if (entry.state === HtlcState.PENDING) {
				entry.state = HtlcState.COMMITTED;
			}
		}

		if (spliceBatch && this._state.spliceInFlight) {
			// Pending splice: announce the batch, then one commitment_signed per
			// active funding output. The bookkeeping above ran ONCE for the whole
			// batch (one logical update, one future revoke_and_ack).
			const startBatch: IStartBatchMessage = {
				channelId: this._state.channelId!,
				batchSize: 2,
				messageType: MessageType.COMMITMENT_SIGNED
			};
			const spliceMsg: ICommitmentSignedMessage = {
				channelId: this._state.channelId!,
				signature: spliceBatch.spliceSignature,
				htlcSignatures: spliceBatch.spliceHtlcSignatures,
				fundingTxid: Buffer.from(this._state.spliceInFlight.spliceTxid)
			};
			const startBatchBytes = encodeStartBatchMessage(startBatch);
			const currentBytes = encodeCommitmentSignedMessage(msg);
			const spliceBytes = encodeCommitmentSignedMessage(spliceMsg);
			// Cache the exact wire bytes so a disconnect straddling this batch can
			// retransmit it verbatim on reestablish (the generic single-message
			// retransmit path cannot: it holds neither the start_batch framing nor
			// the splice-side commitment). Cleared when the peer's revoke_and_ack
			// for this round arrives, or at completeSplice.
			this._lastSentBatch = {
				startBatch: startBatchBytes,
				commitments: [currentBytes, spliceBytes]
			};
			// Persist first: the commitment round we just advanced (and the exact
			// batch bytes, captured into the recovery outbox by the same
			// transition) must be durable before the peer holds our signature.
			return [
				{ type: ChannelActionType.PERSIST_STATE },
				sendMsg(MessageType.START_BATCH, startBatchBytes),
				sendMsg(MessageType.COMMITMENT_SIGNED, currentBytes),
				sendMsg(MessageType.COMMITMENT_SIGNED, spliceBytes)
			];
		}

		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.COMMITMENT_SIGNED, encodeCommitmentSignedMessage(msg))
		];
	}

	/**
	 * Repopulate the un-acked commitment batch from durably stored wire bytes
	 * after a restart (docs/RECOVERY-PROTOCOL.md 5.2, disposition D2).
	 *
	 * Without this the cache dies with the process, and the reestablish
	 * fallback can only REBUILD the batch by re-signing, which it refuses to do
	 * for a taproot channel because a fresh MuSig2 secret nonce must never sign
	 * material the peer may already hold under the old one. Restoring the exact
	 * bytes retransmits without signing anything again.
	 *
	 * Ignored once a batch is already cached: a live batch is never staler than
	 * a stored one.
	 */
	restoreLastSentBatch(startBatch: Buffer, commitments: Buffer[]): void {
		if (this._lastSentBatch) return;
		if (!startBatch || commitments.length === 0) return;
		this._lastSentBatch = {
			startBatch: Buffer.from(startBatch),
			commitments: commitments.map((c) => Buffer.from(c))
		};
	}

	/**
	 * Pending-splice batch signing: the spliced view of the channel state (the
	 * clone re-anchored on the new funding output), for the manager to sign
	 * the peer's splice-side commitment. Null when no splice tx is built.
	 */
	getSplicedStateForSigning(): IChannelState | null {
		return this._splicedState();
	}

	/**
	 * Handle commitment_signed from remote.
	 * Returns revoke_and_ack.
	 */
	handleCommitmentSigned(msg: ICommitmentSignedMessage): ChannelAction[] {
		// A mid-splice commitment_signed that raced our tx_abort belongs to
		// the aborted splice. Classify rather than blanket-ignore: arrival
		// order of the peer's abort echo vs its stray is transport-dependent
		// (see _spliceAbortIgnoreCommitment), so only the message itself can
		// say which it is.
		if (this._spliceAbortIgnoreCommitment) {
			if (this._state.state === ChannelState.SPLICING && this._spliceSession) {
				// A new splice negotiation is live: the peer starts one only
				// after processing our abort, so the old stray (if any) has
				// already been classified. The window is over.
				this._spliceAbortIgnoreCommitment = false;
			} else if (
				msg.fundingTxid &&
				!(
					this._state.fundingTxid &&
					msg.fundingTxid.equals(this._state.fundingTxid)
				)
			) {
				// A funding_txid naming something OTHER than the current funding
				// with no splice context live: this is the aborted splice's
				// stray. Swallow it, and void any start_batch collection it
				// arrived under (a swallowed member would leave the batch
				// permanently short). Keep the guard armed: a stray batch can
				// carry more than one member. A tag that PROVABLY matches the
				// current funding falls through below (a null state fundingTxid
				// degrades to this conservative swallow, never to processing an
				// unproven message).
				this._pendingBatch = null;
				return [];
			} else {
				// Untagged, or tagged with the CURRENT funding txid: legitimate
				// channel traffic (a normal commitment may name its funding tx),
				// so the stream is past the stray. Swallowing it here would
				// drop a real state update and leave the peer waiting for
				// revoke_and_ack. Process it.
				this._spliceAbortIgnoreCommitment = false;
			}
		}
		// Fresh signed traffic ends the reestablish exchange (status machine).
		this._lastReestablishOutcome = null;
		// start_batch collection: buffer the announced batch, then process all
		// of its commitment_signed messages as one logical update.
		if (this._pendingBatch) {
			this._pendingBatch.msgs.push(msg);
			if (this._pendingBatch.msgs.length < this._pendingBatch.size) {
				return [];
			}
			const batch = this._pendingBatch.msgs;
			this._pendingBatch = null;
			return this._handleCommitmentSignedBatch(batch);
		}

		if (this._state.state === ChannelState.SPLICING && this._spliceSession) {
			// Fully signed and awaiting the lock: the channel resumed normal
			// operation, but with TWO active fundings every commitment update
			// MUST arrive as a start_batch of one commitment_signed per funding.
			// A lone commitment_signed here (no preceding start_batch) is invalid
			// and would revoke on only one funding.
			if (this.isSplicePendingLock()) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'commitment_signed during a pending splice must be a start_batch'
					}
				];
			}
			// Mid-splice: the peer sends commitment_signed for the new commitment
			// (spending the spliced funding output) after the interactive tx
			// completes, before tx_signatures. Handle it without revoking the old
			// commitment.
			return this._handleSpliceCommitmentSigned(msg);
		}

		// BOLT 2 v2 establishment: after both tx_completes the peers exchange
		// commitment_signed for commitment #0 of the new funding output, before
		// any tx_signatures. There is no prior commitment to revoke.
		if (
			this._state.state === ChannelState.AWAITING_TX_SIGNATURES &&
			this._state.dualFundingSession
		) {
			return this._handleV2CommitmentSigned(msg);
		}

		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected commitment_signed'
				}
			];
		}

		if (isTaprootChannel(this._state.channelType)) {
			// Cannot verify -> must not adopt, the taproot twin of the ECDSA arm
			// below. A plain ERROR, not a wire error: the missing pieces are a
			// LOCAL invariant failure, not a peer violation, so the channel must
			// not be condemned at the peer. Checked here so the wire-visible arms
			// below can only ever carry a peer-fault reason.
			if (!this._state.localNextNonce || !this._state.remoteBasepoints) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Cannot verify taproot commitment partial: no verification nonce or remote basepoints'
					}
				];
			}
			// Verify the peer's Schnorr sigs over our second-level HTLC txs FIRST
			// (a pure check, no state writes) — _verifyAndStoreRemotePartial
			// overwrites remoteCommitmentSignature/remoteSigningNonce on success,
			// destroying the CURRENT commitment's force-close witness material.
			// If the HTLC sigs then failed, a later force-close would aggregate
			// the next commitment's partial against the current commitment's tx —
			// an invalid, unminable witness. No state may change unless the whole
			// message verifies.
			const htlcPoint = getPerCommitmentPoint(
				this._state.localPerCommitmentSeed,
				this._state.localCommitmentNumber + 1n
			);
			if (
				!verifyRemoteHtlcSignaturesTaproot(
					this._state,
					htlcPoint,
					msg.htlcSignatures
				)
			) {
				// Twin of the wire-visible ECDSA HTLC-sig arm below (BOLT 2 MUST
				// fail the channel).
				return this._failChannelWithWireError('Invalid taproot HTLC signature');
			}
			// option_taproot: verify the peer's MuSig2 partial over OUR next
			// commitment using the verification nonce we advertised one step ahead
			// (localNextNonce) + the peer's inline signing nonce, and store the
			// partial + that signing nonce for force-close aggregation.
			const err = this._verifyAndStoreRemotePartial(
				msg.partialSignatureWithNonce,
				this._state.localNextNonce,
				this._state.localCommitmentNumber + 1n
			);
			if (err) {
				// Twin of the wire-visible ECDSA commitment-sig arm below. The
				// local-invariant reason inside _verifyAndStoreRemotePartial is
				// unreachable past the pre-check above, so err is always a
				// peer-fault reason here.
				return this._failChannelWithWireError(err);
			}
			this._state.remoteHtlcSignatures = msg.htlcSignatures;
		} else {
			// Cannot verify -> must not adopt: the revoke_and_ack this handler
			// returns reveals the previous revocation secret, so an unverified
			// commitment must never make it that far. A plain ERROR, not a wire
			// error: the missing pieces are a LOCAL invariant failure, not a
			// peer violation, so the channel must not be condemned at the peer.
			if (!this._signer || !this._state.remoteBasepoints) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Cannot verify commitment signature: no signer or remote basepoints'
					}
				];
			}

			// Verify the remote's commitment signature BEFORE revoking old state (Fix 1.1)
			const nextCommitmentNumber = this._state.localCommitmentNumber + 1n;
			const nextPerCommitmentPoint = getPerCommitmentPoint(
				this._state.localPerCommitmentSeed,
				nextCommitmentNumber
			);
			const valid = verifyRemoteCommitmentSig(
				this._state,
				this._signer,
				nextPerCommitmentPoint,
				msg.signature,
				nextCommitmentNumber
			);
			if (!valid) {
				const cid = (
					this._state.channelId || this._state.temporaryChannelId
				).toString('hex');
				// BOLT 2: MUST fail the channel — send the wire error so the
				// peer force-closes; continuing would wedge on desynced state.
				return this._failChannelWithWireError(
					`Invalid commitment signature on channel ${cid} (commitNum=${this._state.localCommitmentNumber}, htlcs=${this._state.htlcs.size}, state=${this._state.state})`
				);
			}

			// Verify HTLC second-level transaction signatures before revoking old state
			const htlcSigsValid = verifyRemoteHtlcSignatures(
				this._state,
				this._signer,
				nextPerCommitmentPoint,
				msg.htlcSignatures
			);
			if (!htlcSigsValid) {
				// BOLT 2: MUST fail the channel (see above).
				return this._failChannelWithWireError('Invalid HTLC signature');
			}

			// Store remote's signature
			this._state.remoteCommitmentSignature = msg.signature;
			this._state.remoteHtlcSignatures = msg.htlcSignatures;
		}

		// Record the exact feerate the just-verified signature covers, so a
		// force-close rebuild reproduces this commitment byte-for-byte even if
		// the committed configs move on (fee-update promotion, reestablish
		// rollback, restart).
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);
		this._state.lastSignedCommitLeaseBlockheight =
			getLocalCommitmentLeaseBlockheight(this._state);

		// Two-phase update_fee, acceptor side: this commitment_signed from the
		// opener covers its staged update_fee (the update always precedes its
		// covering signature on the wire), and the revoke_and_ack below locks
		// it in on our side. Only NOW may the new rate be baked into
		// commitments WE sign, and we owe the opener a commitment_signed at
		// the new rate to complete the fee round. Marking the fee "owed" at
		// update_fee RECEIPT (the previous behavior) let unrelated triggers
		// sign at the staged rate before the opener's own commitment expected
		// it — CLN rejects that with "Bad commit_sig".
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			this._state.role === ChannelRole.ACCEPTOR &&
			this._state.pendingFeerateSignable !== true
		) {
			this._state.pendingFeerateSignable = true;
			this._state.needsCommitment = true;
		}

		// update_blockheight, same machine: this commitment_signed from the
		// opener covers its staged height; only NOW may it be baked into
		// commitments WE sign, and we owe a commitment_signed at it.
		if (
			this._state.pendingLeaseBlockheight !== undefined &&
			this._state.role === ChannelRole.ACCEPTOR &&
			this._state.pendingLeaseBlockheightSignable !== true
		) {
			this._state.pendingLeaseBlockheightSignable = true;
			this._state.needsCommitment = true;
		}

		// Two-phase HTLC updates, mirror side: every peer update received
		// before this commitment_signed is covered by it, and the
		// revoke_and_ack below revokes for it. Only NOW may those updates be
		// baked into commitments WE sign, and we owe the peer the
		// commitment_signed that commits them on its side.
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.addLocallyRevoked === false &&
				(entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED)
			) {
				entry.addLocallyRevoked = true;
				this._state.needsCommitment = true;
			}
			if (
				entry.removalLocallyRevoked === false &&
				(entry.state === HtlcState.FULFILLED ||
					entry.state === HtlcState.FAILED)
			) {
				entry.removalLocallyRevoked = true;
				this._state.needsCommitment = true;
			}
		}

		// Reveal current per-commitment secret and advance
		const currentSecret = getPerCommitmentSecret(
			this._state.localPerCommitmentSeed,
			this._state.localCommitmentNumber
		);

		this._state.localCommitmentNumber++;

		// BOLT 2 (revoke_and_ack): next_per_commitment_point is the point for the
		// NEXT commitment transaction — the one after the commitment we just
		// adopted. With commitment M using getPerCommitmentPoint(seed, M) (per
		// channel_ready's second_per_commitment_point = point for commitment #1),
		// the next point is localCommitmentNumber + 1, NOT the just-adopted
		// commitment's own point. Sending localCommitmentNumber here stalled the
		// point chain so every commitment after the first failed verification.
		const nextPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			this._state.localCommitmentNumber + 1n
		);

		// Cache for retransmission on reestablish
		this._state.lastSentRevokeSecret = Buffer.from(currentSecret);
		this._state.lastSentRevokeNextPoint = Buffer.from(nextPoint);
		// Reestablish ordering (BOLT 2): revoke_and_ack is now the most
		// recently sent of {commitment_signed, revoke_and_ack}.
		this._state.lastSentWasRevoke = true;

		// Move pending HTLCs to committed
		for (const entry of this._state.htlcs.values()) {
			if (entry.state === HtlcState.PENDING) {
				entry.state = HtlcState.COMMITTED;
			}
		}

		const revokeMsg: IRevokeAndAckMessage = {
			channelId: this._state.channelId!,
			perCommitmentSecret: currentSecret,
			nextPerCommitmentPoint: nextPoint
		};

		// option_taproot: rotate the verification nonce. The nonce the peer just
		// used to co-sign our now-adopted commitment (localNextNonce) is promoted to
		// the current commitment's nonce (localNonce, reserved for force-close
		// aggregation); we then derive the verification nonce for our NEXT
		// commitment (deterministic per height) and advertise its public part in
		// revoke_and_ack, exactly mirroring next_per_commitment_point. The old
		// localNonce (for the now-revoked commitment) is discarded — its secret is
		// never used again. localCommitmentNumber was just incremented, so the next
		// nonce is for localCommitmentNumber + 1.
		if (isTaprootChannel(this._state.channelType)) {
			this._state.localNonce = this._state.localNextNonce;
			this._state.localNextNonce = this._deriveVerificationNonce(
				this._state.localCommitmentNumber + 1n
			);
			revokeMsg.nextLocalNonce = Buffer.from(this._state.localNextNonce);
		}

		// Persist state BEFORE sending revoke_and_ack (Fix 2.2)
		// Note: HTLC_FORWARDED is NOT emitted here — LND requires a full
		// commitment round-trip before the HTLC can be settled. The event
		// is emitted from handleRevokeAndAck when LND acknowledges.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.REVOKE_AND_ACK, encodeRevokeAndAckMessage(revokeMsg)),
			// An owed stfu reply (issue 431) goes out only after the revoke that
			// completed the drain.
			...this._maybeAnswerOwedStfu()
		];
	}

	/**
	 * Handle revoke_and_ack from remote.
	 */
	handleRevokeAndAck(msg: IRevokeAndAckMessage): ChannelAction[] {
		// Fresh signed traffic ends the reestablish exchange (status machine).
		this._lastReestablishOutcome = null;
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.isSplicePendingLock()
		) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected revoke_and_ack' }
			];
		}

		// The peer acknowledged our latest commitment (batch included): it no
		// longer needs retransmission.
		this._lastSentBatch = null;

		// Bind the revealed secret to the committed per-commitment point BEFORE
		// trusting the revocation. shaChainStore.addSecret only checks
		// secret-to-secret chain consistency; it does not verify that this secret
		// actually corresponds to the per-commitment point used in the commitment
		// being revoked. Without this, a malicious peer could "revoke" with a
		// secret whose pubkey != remoteCurrentPerCommitmentPoint: we would treat
		// the old, higher-balance commitment as revoked, but resolveRevoked-
		// CommitmentOutputs would later derive the WRONG revocation key, every
		// penalty signature would be invalid, and the cheater would sweep their
		// inflated to_local after to_self_delay (BOLT 2 MUST-check).
		if (this._state.remoteCurrentPerCommitmentPoint) {
			const revealedPoint = perCommitmentPointFromSecret(
				msg.perCommitmentSecret
			);
			if (!revealedPoint.equals(this._state.remoteCurrentPerCommitmentPoint)) {
				// BOLT 2: MUST fail the channel — a fake revocation means the peer
				// can still cheat with the "revoked" commitment.
				return this._failChannelWithWireError(
					'revoke_and_ack secret does not match committed per-commitment point'
				);
			}
		}

		// A revoke_and_ack revokes the OLDEST outstanding commitment we signed —
		// index = revocations received so far, NOT remoteCommitmentNumber - 1
		// (the sign counter): with a commitment_signed in flight the two differ,
		// and indexing off the sign counter mis-slotted the revealed secret
		// ("Invalid per-commitment secret" → force close, observed live vs CLN).
		const revocationCount = this._remoteRevocationCountForRaa();
		if (revocationCount >= this._state.remoteCommitmentNumber) {
			// No commitment of ours is outstanding — nothing this could revoke.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected revoke_and_ack: no outstanding commitment'
				}
			];
		}

		// Store the revealed secret
		const expectedIndex = MAX_INDEX - revocationCount;
		const stored = this._state.shaChainStore.addSecret(
			expectedIndex,
			msg.perCommitmentSecret
		);
		if (!stored) {
			// BOLT 2: an unverifiable revocation secret means the peer can cheat
			// with the "revoked" commitment — MUST fail the channel with a wire
			// error, never keep exchanging updates on top of it.
			return this._failChannelWithWireError('Invalid per-commitment secret');
		}

		// The oldest outstanding commitment is now revoked.
		this._state.remoteRevocationNumber = revocationCount + 1n;

		// Update remote's per-commitment point
		this._state.remoteCurrentPerCommitmentPoint =
			this._state.remoteNextPerCommitmentPoint;
		this._state.remoteNextPerCommitmentPoint = msg.nextPerCommitmentPoint;

		// option_taproot: rotate the peer's verification nonce forward in lockstep
		// with their per-commitment point — this nonce is what we use to co-sign the
		// peer's NEXT commitment (matching remoteNextPerCommitmentPoint).
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.nextLocalNonce || msg.nextLocalNonce.length !== 66) {
				// Pure message-content MUST of the taproot extension: every
				// conformant revoke_and_ack, retransmits included, re-attaches
				// the nonce (ours does, deterministically), and without it no
				// further commitment can ever be co-signed.
				return this._failChannelWithWireError(
					'Taproot revoke_and_ack missing a valid next_local_nonce'
				);
			}
			this._state.remoteNonce = msg.nextLocalNonce;
		}

		// The peer's revoke_and_ack acknowledges our last commitment_signed and
		// every update it covered — those no longer need retransmission on
		// reconnect. Updates queued AFTER that signature stay queued for the
		// next round.
		if (this._state.pendingLocalUpdatesSignedCount > 0) {
			this._state.pendingLocalUpdates.splice(
				0,
				this._state.pendingLocalUpdatesSignedCount
			);
			this._state.pendingLocalUpdatesSignedCount = 0;
		}

		// Two-phase updates: this revoke_and_ack answers our one outstanding
		// commitment_signed — every entry it stamped is now irrevocably
		// committed by the peer. Promote the flags so buildLocalCommitment
		// includes our adds (and applies our removals) from the peer's NEXT
		// signature onward — exactly when the peer starts covering them.
		for (const entry of this._state.htlcs.values()) {
			if (entry.commitCoverPending === true) {
				entry.commitCoverPending = false;
				if (
					entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED
				) {
					entry.addRemoteCommitted = true;
				} else {
					entry.removalRemoteCommitted = true;
				}
			}
		}

		// Clean up fulfilled/failed HTLCs and finalize balance changes — but
		// ONLY once the peer has committed the removal (removalRemoteCommitted
		// is false while our removal is still awaiting its covering
		// commitment round; deleting and settling on just any revoke_and_ack
		// moved balances the peer's signatures did not agree to yet).
		for (const [key, entry] of this._state.htlcs) {
			if (entry.removalRemoteCommitted === false) {
				continue;
			}
			if (entry.state === HtlcState.FULFILLED) {
				if (entry.direction === HtlcDirection.RECEIVED) {
					// We received and fulfilled: credit our balance
					this._state.localBalanceMsat += entry.amountMsat;
				} else {
					// We offered and remote fulfilled: credit remote balance
					this._state.remoteBalanceMsat += entry.amountMsat;
				}
				this._state.htlcs.delete(key);
			} else if (entry.state === HtlcState.FAILED) {
				if (entry.direction === HtlcDirection.RECEIVED) {
					// We received but failed: refund remote balance
					this._state.remoteBalanceMsat += entry.amountMsat;
				} else {
					// We offered but it failed: refund our balance
					this._state.localBalanceMsat += entry.amountMsat;
				}
				this._state.htlcs.delete(key);
			}
		}

		// A staged fee update we SIGNED at (pendingFeerateCommitted) is now
		// irrevocably committed on both sides — this revoke_and_ack answers
		// exactly that signature (one commitment outstanding at a time) —
		// promote it to the committed config and clear the staging. A staged
		// fee we have NOT signed at yet must survive: this revoke_and_ack
		// belongs to an earlier round that interleaved with the update_fee,
		// and promoting (or clearing) it here desynced the commitment feerate
		// against CLN.
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			this._state.pendingFeerateCommitted === true
		) {
			if (this._state.role === ChannelRole.OPENER) {
				this._state.localConfig.feeratePerKw = this._state.pendingFeeratePerKw;
			} else {
				this._state.remoteConfig.feeratePerKw = this._state.pendingFeeratePerKw;
			}
			this._state.pendingFeeratePerKw = undefined;
			this._state.pendingFeerateSignable = false;
			this._state.pendingFeerateCommitted = false;
		}

		// update_blockheight, same machine: a staged height we SIGNED at is now
		// irrevocably committed on both sides — promote it (and record it in
		// the height history for on-chain classification of old commitments).
		if (
			this._state.pendingLeaseBlockheight !== undefined &&
			this._state.pendingLeaseBlockheightCommitted === true
		) {
			this._promoteLeaseBlockheight(this._state.pendingLeaseBlockheight);
			this._state.pendingLeaseBlockheight = undefined;
			this._state.pendingLeaseBlockheightSignable = false;
			this._state.pendingLeaseBlockheightCommitted = false;
		}

		// Emit HTLC_FORWARDED for committed received HTLCs that haven't been
		// dispatched yet. This happens AFTER the full commitment round-trip
		// (commitment_signed → revoke_and_ack both ways), ensuring the HTLC
		// is fully committed on both sides before we try to settle it.
		//
		// forwardEmitted makes the dispatch edge-triggered. COMMITTED is not a
		// "needs dispatching" state: a received HTLC sits in it for the entire
		// time its forward is in flight downstream, and only leaves it once we
		// fulfill or fail it. Re-scanning the whole map on every revoke_and_ack
		// therefore re-dispatched every unsettled inbound HTLC on every later
		// commitment round, so the node layer offered a fresh outgoing HTLC each
		// time for one inbound payment — draining outbound liquidity until adds
		// started failing, and leaving several outgoing legs mapped to the same
		// inbound leg.
		const htlcActions: ChannelAction[] = [];
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.state === HtlcState.COMMITTED &&
				entry.direction === HtlcDirection.RECEIVED &&
				entry.forwardEmitted !== true
			) {
				entry.forwardEmitted = true;
				htlcActions.push({
					type: ChannelActionType.HTLC_FORWARDED,
					htlcId: entry.id,
					amountMsat: entry.amountMsat,
					paymentHash: entry.paymentHash
				});
			}
		}

		// Persist state after processing revoke_and_ack (Fix 2.2)
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			...htlcActions,
			// An owed stfu reply (issue 431) goes out once this revoke completed
			// the drain.
			...this._maybeAnswerOwedStfu()
		];
	}

	/**
	 * Update the fee rate (opener only).
	 */
	updateFee(feeratePerKw: number): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			!this.isSplicePendingLock()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot update fee: wrong state'
				}
			];
		}

		if (this._state.role !== ChannelRole.OPENER) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Only opener can update fee' }
			];
		}

		// BOLT 2 quiescence: "MUST NOT send an update message after stfu". The
		// manager defers settles on a quiescing channel before reaching here;
		// this guard covers callers driving the Channel directly.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot update fee: channel is quiescing'
				}
			];
		}

		// Bounds checking: never propose a feerate outside the absolute limits the
		// acceptor enforces in handleUpdateFee (253 sat/kw floor, 100000 ceiling).
		// We deliberately do NOT mirror the acceptor's soft 10x-relative cap here:
		// a genuine mempool spike can require raising the feerate more than 10x off
		// the 253 floor, and self-limiting would leave us unable to fund a viable
		// commitment when we most need to.
		if (feeratePerKw < 253) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate below minimum relay fee (253 sat/kw)'
				}
			];
		}
		if (feeratePerKw > 100_000) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate above absolute maximum (100000 sat/kw)'
				}
			];
		}

		// Reject a feerate that would drain our (the opener's) balance below
		// reserve, matching the acceptor's reserve guard. Priced at what the
		// builder actually takes off the funder: the fee at this channel type's
		// base weight plus the anchor outputs it deducts separately (#193, #403),
		// or the promoted rate produces a commitment the reserve check would have
		// refused.
		const activeHtlcCount = this._countActiveHtlcs();
		const newCost = funderCommitmentCostSats(
			feeratePerKw,
			activeHtlcCount,
			this._state.channelType
		);
		const reserveMsat = this._state.remoteConfig.channelReserveSatoshis * 1000n;
		let headroomMsat = this._state.localBalanceMsat - reserveMsat;
		// While a splice awaits its lock the fee round mirrors onto the pending
		// funding too, whose balance AND reserve both differ (a splice-out's
		// candidate has less to spend; the pending capacity prices its own
		// reserve). Bind on whichever view affords less, exactly as
		// getSpendableOutboundMsat does for adds.
		const pendingBalanceMsat = this.getPendingSpliceLocalBalanceMsat();
		const pendingReserveSats = this._pendingSpliceKeptReserveSats();
		if (pendingBalanceMsat !== null && pendingReserveSats !== null) {
			const pendingHeadroomMsat =
				pendingBalanceMsat - pendingReserveSats * 1000n;
			if (pendingHeadroomMsat < headroomMsat) {
				headroomMsat = pendingHeadroomMsat;
			}
		}
		if (newCost * 1000n > headroomMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate would drain opener below channel reserve'
				}
			];
		}

		// Dust re-trim guard (mirror of handleUpdateFee): never propose a rate
		// that would trim our own in-flight HTLCs — same loss mode, self-inflicted.
		if (
			this._dustExposureAtRateMsat(feeratePerKw) >
			Channel.MAX_DUST_HTLC_EXPOSURE_MSAT
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'update_fee would raise dust HTLC exposure above limit (in-flight HTLCs would be trimmed)'
				}
			];
		}

		// One fee round at a time: once the staged rate is baked into a
		// commitment_signed we sent (committed), overwriting it would promote a
		// rate the peer never saw in that signature when its revoke_and_ack
		// arrives. Propose again after the in-flight round settles.
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			this._state.pendingFeerateCommitted === true
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Previous fee update still committing'
				}
			];
		}

		// Stage the new feerate as pending — do NOT apply it to the committed
		// config yet. It is used for the commitment built in this round and only
		// promoted to localConfig.feeratePerKw once the round irrevocably commits
		// (handleRevokeAndAck). If a restart interrupts the round, reestablish
		// rolls it back, avoiding a permanent commitment-fee desync.
		this._state.pendingFeeratePerKw = feeratePerKw;
		this._state.pendingFeerateSignable = false;
		this._state.pendingFeerateCommitted = false;

		const msg: IUpdateFeeMessage = {
			channelId: this._state.channelId!,
			feeratePerKw
		};

		// Fee change is an update — we owe the remote a commitment_signed.
		this._state.needsCommitment = true;

		const payload = encodeUpdateFeeMessage(msg);
		// BOLT 2 reestablish: like every update, the peer forgets an
		// uncommitted update_fee across a disconnect — queue it so a
		// reconnect replays it BEFORE any retransmitted commitment_signed
		// (whose cached bytes were signed at the new rate).
		this._queuePendingLocalUpdate(MessageType.UPDATE_FEE, payload);

		// Persist the staged rate and its queued retransmission entry before
		// the peer sees the update.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.UPDATE_FEE, payload)
		];
	}

	/**
	 * Handle update_fee from remote.
	 */
	handleUpdateFee(msg: IUpdateFeeMessage): ChannelAction[] {
		// A fully-signed splice awaiting its lock resumes normal update traffic
		// (CLN routinely sends update_fee in this window). BOLT 2 also allows
		// update_fee during shutdown while HTLCs remain (CLN sends it), exactly
		// like the other update_* messages — rejecting it force-closed a channel
		// that was shutting down cleanly.
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.isSplicePendingLock()
		) {
			// Same split as handleUpdateAddHtlc's lifecycle guard. There is no
			// crossing case to carve out here, because update_fee is legal during
			// shutdown and SHUTTING_DOWN never reaches this arm; what is left is a
			// channel that has moved to CLOSING, ERRORED or an unlocked splice.
			// LOCAL for the reasons handleUpdateAddHtlc's guard sets out: nothing
			// cascades from a refused update_fee in these states, and update_fee is
			// itself replayed by handleReestablish, so wire-failing it would condemn
			// a peer doing what BOLT 2 requires.
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_fee',
					cleanup: 'none'
				}
			];
		}

		if (this._state.role !== ChannelRole.ACCEPTOR) {
			// BOLT 2 MUST fail: only the node responsible for paying the commitment
			// fee may send update_fee.
			return this._failChannelWithWireError('Only opener can send update_fee');
		}

		// Bounds checking: reject unreasonable fee rates
		if (msg.feeratePerKw < 253) {
			// BOLT 2: a rate too low for the commitment to relay is a fail-the-channel
			// condition for the receiver.
			return this._failChannelWithWireError(
				'Fee rate below minimum relay fee (253 sat/kw)'
			);
		}

		// Absolute ceiling (matches the open_channel validation): even within the
		// 10x relative bound, never accept an absurd feerate that would burn the
		// channel balance as commitment fees.
		if (msg.feeratePerKw > 100_000) {
			// BOLT 2: an unreasonably large rate is a fail-the-channel condition.
			return this._failChannelWithWireError(
				'Fee rate above absolute maximum (100000 sat/kw)'
			);
		}

		// Measured against the highest rate already in play, not only the COMMITTED
		// one. BOLT 2 lets the opener send several update_fee inside one round and
		// counts the last, but pendingFeeratePerKw is promoted into remoteConfig
		// only when a staged rate reaches the signable phase or the round
		// completes, so measuring the second update of a round against the stale
		// committed rate refused a legal escalation (253 -> 2530 -> 25300). It only
		// ever loosens, and the absolute ceiling above still bounds a runaway.
		// Getting this right is a precondition for the wire error below: a guard
		// that fails the channel must not carry known false positives.
		const currentRate = Math.max(
			this._state.pendingFeeratePerKw ?? 0,
			this._state.remoteConfig.feeratePerKw || 253
		);
		if (msg.feeratePerKw > currentRate * 10) {
			return this._failChannelWithWireError(
				'Fee rate unreasonably high (>10x current rate)'
			);
		}

		// Check whether the new fee rate would drain the opener below channel
		// reserve, against what the builder actually takes off the funder: the fee
		// at this channel type's base weight plus the anchor outputs it deducts on
		// top (#193). Over-pricing it here refuses an update_fee that is legal by
		// the opener's own arithmetic, and since issue 404 that refusal fails the
		// channel outright rather than desyncing it silently, so this arithmetic has
		// to match the opener's exactly (#403).
		const activeHtlcCount = this._countActiveHtlcs();
		const newCost = funderCommitmentCostSats(
			msg.feeratePerKw,
			activeHtlcCount,
			this._state.channelType
		);
		const reserveMsat = this._state.localConfig.channelReserveSatoshis * 1000n;
		// Remote is the opener (we are acceptor), so check their balance
		if (newCost * 1000n > this._state.remoteBalanceMsat - reserveMsat) {
			// BOLT 2: a rate the opener cannot afford above its reserve can never be
			// applied to the commitment we hold.
			return this._failChannelWithWireError(
				'Fee rate would drain opener below channel reserve'
			);
		}

		// Dust re-trim guard: on non-anchor channels the trim threshold rises
		// with the feerate, so a fee hike can push previously-untrimmed in-flight
		// HTLCs below dust — silently burning their value into the commitment
		// fee. Reject a feerate that would raise total dust exposure above the
		// same ceiling enforced at HTLC-add time. Rejecting is safe because the
		// wire error below force-closes at the old COMMITTED rate, where the HTLCs
		// are still untrimmed and claimable. That was not true while this returned a
		// bare ERROR: the peer never heard, kept the rate in its book, and the
		// channel died a round later on a signature mismatch instead (issue 404).
		if (
			this._dustExposureAtRateMsat(msg.feeratePerKw) >
			Channel.MAX_DUST_HTLC_EXPOSURE_MSAT
		) {
			// Unlike the HTLC-add arms (issue 410), this one stays a channel
			// failure: BOLT 2's dust-exposure section says the receiver of such an
			// update_fee "MAY fail the channel" (eclair and CLN do), and there is
			// no per-HTLC answer to a fee update that re-trims the whole in-flight
			// set.
			return this._failChannelWithWireError(
				'update_fee would raise dust HTLC exposure above limit (in-flight HTLCs would be trimmed)'
			);
		}

		// The reserve check above measures the opener against the reserve WE
		// enforce, which on an asymmetric-dust channel can sit below our own
		// dust limit: a fee hike can then take the opener's balance under it
		// while ours is already there, leaving the commitment we hold with no
		// outputs at all (issue #386). Staging the rate is what makes it bite,
		// since our local commitment builds at the staged rate from the moment
		// it is accepted, so this must run BEFORE anything below is written or a
		// refusal would promote a rate for a round that never happens.
		const wouldEmpty = this._localCommitmentEmptyRefusal({
			pendingFeeratePerKw: msg.feeratePerKw
		});
		if (wouldEmpty) {
			return this._failChannelWithWireError(wouldEmpty);
		}

		// Stage the opener's proposed feerate as pending rather than applying it to
		// remoteConfig immediately. It is promoted to the committed config once the
		// round finalizes, and rolled back on reestablish if interrupted — keeping
		// our commitment fee in lockstep with the opener's.
		//
		// Two-phase (BOLT 2, mirrors CLN's fee state machine): from here the
		// staged rate applies to verifying the opener's signatures over OUR
		// commitment (the opener bakes its own fee into everything it signs from
		// the moment it sends update_fee). It must NOT yet apply to commitments
		// WE sign, and we do NOT owe a commitment_signed yet: that happens only
		// after the opener's covering commitment_signed arrives and we revoke
		// (handleCommitmentSigned sets pendingFeerateSignable + needsCommitment).
		// Setting needsCommitment here let any unrelated trigger (our own HTLC
		// add/fulfill, a prior round's revoke_and_ack) sign the opener's
		// commitment at the new rate while the opener still expected the old one
		// — "Bad commit_sig" at CLN, force close (observed live).
		//
		// A NEW update_fee while a previous staged rate already reached the
		// signable phase: the previous rate is locked into the exchange (the
		// opener saw our revocation for its covering commitment and expects our
		// signatures at it until THIS one completes its own half-round) —
		// promote it to the committed config before staging the replacement.
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			this._state.pendingFeerateSignable === true
		) {
			this._state.remoteConfig.feeratePerKw = this._state.pendingFeeratePerKw;
		}
		this._state.pendingFeeratePerKw = msg.feeratePerKw;
		this._state.pendingFeerateSignable = false;
		this._state.pendingFeerateCommitted = false;
		return [];
	}

	/**
	 * bLIP-0051 update_blockheight (type 137): the OPENER of a leased channel
	 * advances the agreed blockheight, shrinking the lessor's remaining-lease
	 * CSV (lease_csv = lease_expiry - blockheight) in the commitment scripts.
	 * We only ever RECEIVE this (the lessor is always the acceptor); the staged
	 * height runs the same two-phase machine as update_fee — it applies to the
	 * opener's signatures immediately and to commitments WE sign only once
	 * signable, and is promoted on round completion. Ignoring the message (the
	 * old behavior: type 137 is odd, so it was dropped) desynced every
	 * subsequent commitment script against a CLN buyer.
	 */
	handleUpdateBlockheight(msg: IUpdateBlockheightMessage): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!this.isSplicePendingLock()
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_blockheight'
				}
			];
		}

		// Only the opener sends update_blockheight (CLN channeld enforces the
		// same on both sides, and fails the channel; now we tell the peer too).
		// Roles were fixed at open, so nothing in flight can excuse it.
		if (this._state.role !== ChannelRole.ACCEPTOR) {
			return this._failChannelWithWireError(
				'Only the opener can send update_blockheight'
			);
		}

		// Only meaningful on a leased channel where WE are the lessor: the
		// height feeds our lease CSV. CLN fails the channel for it too, and the
		// lease's existence is a fact both sides fixed at open.
		if (this._state.leaseExpiry === undefined || !this._state.isLessor) {
			return this._failChannelWithWireError(
				'update_blockheight on a non-leased channel'
			);
		}

		// Monotonic: the agreed blockheight never decreases (CLN warns and
		// fails). An equal height is a harmless no-op. The comparison only ever
		// sees heights the opener itself put on the wire: markForReestablish
		// discards an uncommitted staged height on disconnect, so no legal
		// replay compares against state the peer never learned of.
		const current =
			this._state.pendingLeaseBlockheight ??
			this._state.leaseCommitBlockheight ??
			0;
		if (msg.blockheight < current) {
			return this._failChannelWithWireError(
				`update_blockheight decreased (${msg.blockheight} < ${current})`
			);
		}
		if (msg.blockheight === current) {
			return [];
		}

		// Staleness (CLN parity, which fails the channel): a height more than
		// 1008 blocks behind our own tip means the opener's view is unusably
		// old. Our-tip policy, told anyway, like the CLTV horizon (issue 404).
		if (
			this._currentBlockHeight > 0 &&
			msg.blockheight + 1008 < this._currentBlockHeight
		) {
			return this._failChannelWithWireError(
				`update_blockheight too old (${msg.blockheight} vs tip ${this._currentBlockHeight})`
			);
		}

		// A NEW update while a previous staged height already reached the
		// signable phase: the previous height is locked into the exchange —
		// promote it before staging the replacement (mirrors update_fee).
		if (
			this._state.pendingLeaseBlockheight !== undefined &&
			this._state.pendingLeaseBlockheightSignable === true
		) {
			this._promoteLeaseBlockheight(this._state.pendingLeaseBlockheight);
		}
		this._state.pendingLeaseBlockheight = msg.blockheight;
		this._state.pendingLeaseBlockheightSignable = false;
		this._state.pendingLeaseBlockheightCommitted = false;
		return [];
	}

	/**
	 * Promote a lease blockheight to the committed config and record it in the
	 * height history (on-chain classification of OLD commitments needs every
	 * height that was ever committed to rebuild their lease-locked scripts).
	 */
	private _promoteLeaseBlockheight(height: number): void {
		if (this._state.leaseCommitBlockheight !== height) {
			const history = this._state.leaseHeightHistory ?? [];
			if (
				this._state.leaseCommitBlockheight !== undefined &&
				history[history.length - 1] !== this._state.leaseCommitBlockheight
			) {
				history.push(this._state.leaseCommitBlockheight);
			}
			history.push(height);
			this._state.leaseHeightHistory = history;
		}
		this._state.leaseCommitBlockheight = height;
	}

	// ─────────────── Closing ───────────────

	/**
	 * Reconcile the channel state with a close that was observed on-chain — e.g. a
	 * remote force-close or a completed cooperative close detected by the chain
	 * watcher after a restart, where the spend happened while we were offline.
	 *
	 * @param force true if the funding output was spent by a commitment tx
	 *   (force close), false for a cooperative close.
	 * @returns true if the state actually changed, false if the channel was
	 *   already in a closed state (idempotent).
	 */
	markClosedOnChain(force: boolean): boolean {
		// A commitment spend can REPLACE a recorded cooperative close (reorg
		// swap while the mutual close waits out its anti-reorg depth, issue
		// 353). The channel sits in CLOSED from the coop classification, but the
		// close that is actually confirmed is now unilateral: escalate so the
		// force-close lifecycle (pending-close balance, events, restore repair)
		// applies in this session instead of only after a restart.
		if (this._state.state === ChannelState.CLOSED) {
			if (!force) return false;
			this._state.state = ChannelState.FORCE_CLOSED;
			return true;
		}
		if (this._state.state === ChannelState.FORCE_CLOSED) {
			return false;
		}
		this._state.state = force ? ChannelState.FORCE_CLOSED : ChannelState.CLOSED;
		return true;
	}

	/**
	 * Mark a closing channel as fully resolved on-chain — every tracked output
	 * of the closing transaction has been irrevocably swept/claimed (the chain
	 * monitor reached FULLY_RESOLVED). Transitions the channel to CLOSED so it
	 * stops counting toward pending-close balances.
	 *
	 * @returns true if the state actually changed, false if the channel was not
	 *   in a closing state (idempotent).
	 */
	markResolved(): boolean {
		if (
			this._state.state !== ChannelState.FORCE_CLOSED &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.NEGOTIATING_CLOSING
		) {
			return false;
		}
		this._state.state = ChannelState.CLOSED;
		return true;
	}

	/**
	 * Force close the channel by broadcasting the latest local commitment.
	 * Returns the commitment transaction to broadcast and a CHANNEL_CLOSED action.
	 */
	/**
	 * Per-channel recovery status (docs/RECOVERY-PROTOCOL.md 5.6). Derived,
	 * not stored: the two stale-side states come from their persisted flags,
	 * the exchange states from where reestablish stands this session.
	 * Precedence: proven stale beats everything (the never-broadcast
	 * invariant rides that flag through any lifecycle state), then
	 * unprovable, then the terminal close, then the exchange.
	 */
	getRecoveryStatus(): ChannelRecoveryStatus {
		const s = this._state;
		if (s.dataLossDetected) return ChannelRecoveryStatus.LocalDataLoss;
		if (s.stateUncertain) return ChannelRecoveryStatus.StateUncertain;
		if (
			s.state === ChannelState.FORCE_CLOSED ||
			s.state === ChannelState.ERRORED
		) {
			// ...unless the capsule restore hold is on, in which case no
			// automatic close will ever run and reporting ForceClosing would
			// tell an operator a close is under way when the channel is
			// waiting on the peer or on them (issue #469).
			if (
				s.state === ChannelState.ERRORED &&
				s.restoreRecencyUnproven === true
			) {
				return ChannelRecoveryStatus.RestoreRecencyUnproven;
			}
			// ERRORED without a stale flag is recovered by broadcasting our
			// latest commitment (the BOLT 1 prescription for a received
			// error), so it is on the force-close path.
			return ChannelRecoveryStatus.ForceClosing;
		}
		if (s.state === ChannelState.AWAITING_REESTABLISH) {
			return ChannelRecoveryStatus.Quarantined;
		}
		if (this._lastReestablishOutcome === 'replay') {
			return ChannelRecoveryStatus.ReplayRequired;
		}
		if (
			this._lastReestablishOutcome === 'clean' &&
			s.state !== ChannelState.NORMAL
		) {
			// Counters agreed but the channel resumed into a non-quiescent
			// state (a splice mid-flight, a pending shutdown): still resuming.
			return ChannelRecoveryStatus.Reestablishing;
		}
		return ChannelRecoveryStatus.Active;
	}

	/**
	 * The recovery-close disposition as an INVARIANT, not a field lookup:
	 * restart liveness must not depend on every ERRORED transition having
	 * remembered to assign a redundant field. The explicit reason wins when
	 * present; otherwise it derives from the durable safety flags, which
	 * covers states created by SCB recovery, by early reestablish validation
	 * failures, and by databases written before the field existed.
	 */
	getRecoveryCloseReason(): RecoveryCloseReason | undefined {
		if (this._state.recoveryCloseReason) {
			return this._state.recoveryCloseReason;
		}
		if (this._state.dataLossDetected) return 'local-data-loss';
		if (this._state.stateUncertain) return 'state-uncertain';
		// A capsule-restored row the peer has not confirmed yet (issue #469).
		// DERIVED and never stamped by _ensureRecoveryCloseDisposition, unlike
		// the two above: deriving keeps the disposition answerable to the flag
		// rather than to a field some transition remembered to set. It is what
		// stops the automatic-close gate becoming a trapdoor: an
		// ERRORED row never reaches Channel.handleReestablish at all, because
		// ChannelManager answers a reestablish for one with a wire error, so
		// without a peer-close request such a channel would wait forever with
		// nothing driving it anywhere.
		if (this._state.restoreRecencyUnproven) return 'restore-unproven';
		return undefined;
	}

	/** ERRORED and waiting for the PEER's close: reconnect must chase it. */
	hasRecoveryCloseDisposition(): boolean {
		return (
			this._state.state === ChannelState.ERRORED &&
			this.getRecoveryCloseReason() !== undefined
		);
	}

	/**
	 * Stamp the explicit disposition from the safety flags before an ERRORED
	 * transition persists, so the stored row is self-describing even where
	 * the derived fallback would already cover it.
	 */
	private _ensureRecoveryCloseDisposition(): void {
		if (this._state.recoveryCloseReason) return;
		if (this._state.dataLossDetected) {
			this._state.recoveryCloseReason = 'local-data-loss';
		} else if (this._state.stateUncertain) {
			this._state.recoveryCloseReason = 'state-uncertain';
		}
	}

	/**
	 * An irrecoverable reestablish counter gap on a channel whose automatic
	 * closes are held (issue #469).
	 *
	 * These two branches are a dead end by construction: the peer names a
	 * commitment or revocation this node never produced, so nothing can be
	 * retransmitted and the exchange cannot complete. On an ordinary channel
	 * that is survivable, because the reestablish-timeout backstop force-closes
	 * it after `reestablishTimeoutBlocks`. On a held one that backstop is
	 * refused forever, and the bare error these used to return leaves the
	 * channel in AWAITING_REESTABLISH with no durable disposition, so
	 * hasRecoveryCloseDisposition stays false and not even the peer-close
	 * request goes out: a channel with no exit at all.
	 *
	 * So the failure is made terminal and durable here, which is what puts it
	 * on the 5.6 path the hold already assumes: ERRORED plus a persist, after
	 * which the derived `restore-unproven` disposition asks the peer to close
	 * on this and every later reconnect.
	 */
	private _heldReestablishGapFailure(message: string): ChannelAction[] {
		if (this._state.restoreRecencyUnproven !== true) {
			return [{ type: ChannelActionType.ERROR, message }];
		}
		this._state.state = ChannelState.ERRORED;
		return [
			// Persist FIRST, exactly as the DLP arms above: a crash between
			// this and the socket must not forget that the peer has to close.
			{ type: ChannelActionType.PERSIST_STATE },
			...this.buildRecoveryCloseActions().filter(
				(a) => a.type !== ChannelActionType.PERSIST_STATE
			),
			{ type: ChannelActionType.ERROR, message }
		];
	}

	/**
	 * The durable peer-close request (recovery 5.6). The original wire error
	 * can be lost to a crash between the ERRORED persist and the socket
	 * (ERROR is deliberately not in the retransmission outbox), so the
	 * persisted DISPOSITION regenerates it deterministically on every
	 * reconnect until the peer's close resolves the channel on chain.
	 */
	buildRecoveryCloseActions(): ChannelAction[] {
		const reason = this.getRecoveryCloseReason();
		if (!reason || !this._state.channelId) return [];
		const data =
			reason === 'local-data-loss'
				? 'peer proved our channel state is stale (data loss); awaiting your force close'
				: reason === 'restore-unproven'
				? 'restored channel state has not been confirmed by channel_reestablish (recovery); awaiting your force close'
				: 'restored channel state cannot be proven current (recovery); awaiting your force close';
		return [
			// The persist leads, exactly as it does at the two sites that first
			// declare this disposition, and for a second reason here: under a
			// quorum barrier (5.8) a data-loss error may not reach the peer
			// before the frame authorizing it has guardian receipts, and the
			// batch's own PERSIST_STATE is the only thing that names that
			// frame. Regenerating the error alone would hand the wire a
			// declaration no receipt covers. The state written is the same
			// state that was already committed, so the cost is one no-op frame
			// per reconnect of a channel that is only waiting to be closed.
			{ type: ChannelActionType.PERSIST_STATE },
			declMsg(
				MessageType.ERROR,
				encodeErrorMessage({
					channelId: this._state.channelId,
					data: Buffer.from(data, 'ascii')
				})
			)
		];
	}

	/**
	 * Re-mint the authorization a RESTART lost, for a v1 funding transaction
	 * this node is already obliged to broadcast.
	 *
	 * The obligation itself survives a restart, because the peer's signature
	 * over our commitment #0 is on disk. The AUTHORIZATION does not, and the
	 * two are not the same thing. Under a quorum barrier the original
	 * authorization may have been held when the process died, and a local
	 * frame is not a quorum-durable one: restoring a channel row proves this
	 * device wrote the frame, never that the guardians accepted it. So the
	 * restart asks again, through a fresh persist whose frame the barrier can
	 * actually wait on, exactly as the recovery-close declaration does.
	 *
	 * Restored channel state may determine that an authorization is NEEDED. It
	 * must never be the authorization.
	 */
	buildFundingReauthorizationActions(): ChannelAction[] {
		const fundingTxid = this._state.fundingTxid;
		if (!fundingTxid) return [];
		// The same two conditions the live path establishes at funding_signed.
		if (this._state.state === ChannelState.SENT_FUNDING_CREATED) return [];
		if (!this._state.remoteCommitmentSignature) return [];
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.AUTHORIZE_FUNDING_BROADCAST,
				fundingTxid
			}
		];
	}

	/**
	 * Start the BOLT 2 forget clock for a funding neither mempool nor chain can
	 * find. Returns true when THIS call started it, which is the caller's
	 * signal that the new height owes a persist: the clock counts down to
	 * destroying a channel, so it must be read back after a restart rather
	 * than restarted from whatever height the node happens to be at then.
	 * Idempotent afterwards, so every later absence keeps the original height.
	 */
	beginFundingMissingClock(height: number): boolean {
		// A non-positive height is not a height: it is the node saying it has
		// no chain tip yet (currentBlockHeight starts at 0 and only a header
		// the backend actually delivered replaces it). Stamping it would
		// record "missing since the genesis block", and the next absence at a
		// real tip would then measure a wait of the whole chain and forget a
		// funding that was never given its 2016 blocks. Absence that cannot be
		// timed does not start a clock; the caller retains the channel and
		// asks again (issue #463).
		if (!Number.isFinite(height) || height <= 0) return false;
		if (this.fundingMissingSince() !== undefined) return false;
		this._state.fundingMissingSinceHeight = height;
		return true;
	}

	/**
	 * The height absence was first observed at, or undefined if never. A
	 * non-positive stored value reads as unset: rows written before the guard
	 * above existed can carry a 0 stamped with no tip, and that is not a
	 * countdown anyone may act on. Reporting it as unset lets the next real
	 * absence restamp it at a height that means something.
	 */
	fundingMissingSince(): number | undefined {
		const since = this._state.fundingMissingSinceHeight;
		if (since === undefined || !Number.isFinite(since) || since <= 0) {
			return undefined;
		}
		return since;
	}

	/**
	 * Stop the clock: the funding was found, so nothing is counting down any
	 * more. Returns true when this call cleared a running clock, so the caller
	 * knows the removal is a state change that owes a persist of its own.
	 * Keyed on the raw field rather than fundingMissingSince(), so an unusable
	 * stamp still gets removed from disk instead of lingering forever.
	 */
	clearFundingMissingClock(): boolean {
		if (this._state.fundingMissingSinceHeight === undefined) return false;
		delete this._state.fundingMissingSinceHeight;
		return true;
	}

	/**
	 * Retire the retained funding payload, which lives with the broadcast
	 * obligation it serves. Returns true when this call dropped one.
	 */
	clearRetainedFundingPayload(): boolean {
		if (this._state.pendingFundingTxHex === undefined) return false;
		delete this._state.pendingFundingTxHex;
		return true;
	}

	/**
	 * The same re-authorization for a fully signed splice resumed at startup.
	 *
	 * Startup used to hand the retained hex straight to the chain backend,
	 * which is outside the action model entirely: no frame, no persist gate and
	 * no barrier. A splice creates a funding output exactly as an open does, so
	 * it answers to the same rule.
	 */
	buildSpliceRebroadcastActions(): ChannelAction[] {
		const inflight = this._state.spliceInFlight;
		if (!inflight?.fullySigned || !inflight.spliceTxHex) return [];
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.BROADCAST_TX,
				tx: Buffer.from(inflight.spliceTxHex, 'hex'),
				fundingCritical: true
			}
		];
	}

	/**
	 * Force close, in one call: plan, then apply.
	 *
	 * Kept for callers with nothing to sequence between the two. The operator
	 * path does NOT use it: abandoning a held barrier queue is irreversible,
	 * so it has to happen after the plan is known to be possible and before
	 * the live channel moves, which is the whole reason the two halves exist.
	 */
	forceClose(signer: ISigner): ChannelAction[] {
		const plan = this.prepareForceClose(signer);
		if (!plan.ok) {
			return [{ type: ChannelActionType.ERROR, message: plan.error }];
		}
		return this.applyForceClosePlan(plan);
	}

	/**
	 * Decide whether this channel can force close, and build the commitment it
	 * would broadcast, WITHOUT touching the live channel.
	 *
	 * This used to be one method that mutated as it went: it adopted a
	 * confirmed splice (swapping the funding outpoint, the capacity, both
	 * balances and the signature material, and resetting the splice runtime)
	 * and wrote the taproot verification nonce, and only then reached checks
	 * that could still refuse. A refusal therefore left a channel that had
	 * already moved, while a Phase 6 barrier could still be holding a batch
	 * built against the state it moved from. That batch releases later against
	 * a channel that no longer matches it. "In memory and unpersisted" is not
	 * a mitigation: an unpersisted mutation underneath a persisted, queued
	 * batch is exactly the divergence.
	 *
	 * So every refusal is decided here, against a CANDIDATE view, and the
	 * commitment is built against that same view. Once this returns ok the
	 * caller may burn its irreversible bridges before applying.
	 */
	prepareForceClose(signer: ISigner): ForceClosePlan {
		// The recovery never-broadcast invariant (5.6): proven stale
		// (dataLossDetected) or unprovable (stateUncertain), our latest local
		// commitment may be revoked in the peer's view - broadcasting it hands
		// our entire balance to the justice path. Recovery is passive:
		// StateUncertain is permanent absent independently verified storage
		// provenance, so the only exit is the peer force-closing with ITS
		// commitment; we sweep our to_remote from that.
		if (mustNotBroadcastCommitment(this._state)) {
			return {
				ok: false,
				error: this._state.dataLossDetected
					? 'Refusing to broadcast stale commitment after data loss'
					: 'Refusing to broadcast: restored state is not proven current'
			};
		}

		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY &&
			this._state.state !== ChannelState.AWAITING_REESTABLISH &&
			// A channel the peer failed (ERRORED) or one wedged mid-splice is
			// recovered by broadcasting our latest commitment — that IS the
			// BOLT 1 prescription for a received error.
			this._state.state !== ChannelState.ERRORED &&
			this._state.state !== ChannelState.SPLICING &&
			// Re-running on FORCE_CLOSED rebuilds the byte-identical commitment
			// (deterministic signatures): the rebroadcast path when the first
			// broadcast never reached the network. If it confirmed meanwhile the
			// network simply rejects the duplicate.
			this._state.state !== ChannelState.FORCE_CLOSED
		) {
			return { ok: false, error: 'Cannot force close: wrong state' };
		}

		// The taproot peer nonce is asked FIRST, before anything else is even
		// computed, because nothing else affects it: a splice adoption does not
		// touch remoteSigningNonce. It used to be asked after our own
		// verification nonce had already been written to live state.
		const taproot = isTaprootChannel(this._state.channelType);
		if (taproot && !this._state.remoteSigningNonce) {
			return {
				ok: false,
				error:
					'Cannot force close taproot channel: missing peer signing nonce (remoteSigningNonce) for the current commitment'
			};
		}

		// A splice tx that CONFIRMED makes the old funding output unspendable —
		// a live-state commitment would spend a spent outpoint and can never
		// confirm, leaving no unilateral exit. The only valid exit is the
		// commitment on the NEW funding, whose peer signatures the
		// point-of-no-return record carries; so the close is planned against
		// the spliced view (the same swap of outpoint, balances and signature
		// material a splice_locked exchange makes — the peer's signatures are
		// over commitment N regardless of whether splice_locked ever crossed).
		//
		// Judged by the CONFIRMED record alone, never by channel state: the
		// production shapes are a disconnect wrapping SPLICING in
		// AWAITING_REESTABLISH (where the chain watcher records the confirmation
		// it could not announce), and a BOLT 1 error landing mid-splice, where
		// markErrored has already replaced SPLICING with ERRORED by the time the
		// close is driven. A state-based gate would skip adoption in the latter
		// and broadcast against the spent pre-splice funding.
		let spliceAdoption: Partial<IChannelState> | null = null;
		const inflight = this._state.spliceInFlight;
		if (inflight?.confirmed === true) {
			// Without the peer's signature over the POST-splice commitment,
			// adopting would leave remoteCommitmentSignature holding the
			// PRE-splice one: non-null, so the check further down passes, and
			// useless, because it signs an output this splice has spent. That
			// produces a commitment the network rejects while this method
			// reports a successful close.
			if (!this.spliceAdoptedRemoteSignature()) {
				return {
					ok: false,
					error:
						'Cannot force close: confirmed splice has no remote commitment signature to adopt'
				};
			}
			spliceAdoption = this._computeSpliceAdoption();
			// Never knowingly broadcast a commitment against the spent
			// pre-splice funding: if the adoption would not actually swap the
			// outpoint, refuse rather than produce an unconfirmable exit.
			const expectedTxid = Buffer.from(inflight.spliceTxid);
			if (
				!spliceAdoption?.fundingTxid?.equals(expectedTxid) ||
				spliceAdoption.fundingOutputIndex !== inflight.newFundingOutputIndex
			) {
				return {
					ok: false,
					error:
						'Cannot force close: confirmed splice funding could not be adopted'
				};
			}
			if (this._state.state === ChannelState.ERRORED) {
				// The adoption restores NORMAL exactly as a splice_locked
				// exchange would; a channel failed by a BOLT 1 error stays failed.
				spliceAdoption.state = ChannelState.ERRORED;
				spliceAdoption.preReestablishState = null;
			} else if (spliceAdoption.state === ChannelState.NORMAL) {
				// Adoption succeeded from inside the reestablish wrapper: the
				// wrapper's return-to state no longer exists.
				spliceAdoption.preReestablishState = null;
			}
		}

		// A superseded RBF attempt that won the confirmation race while we
		// could not act on it (see _computeV2ConfirmedAdoption): close against
		// the funding that is actually on chain, not against the replacement
		// it beat.
		const v2Adoption = this._computeV2ConfirmedAdoption();
		if (v2Adoption && !v2Adoption.remoteCommitmentSignature) {
			// Same reasoning as the splice arm above: adopting an attempt whose
			// commitment exchange never completed would leave the REPLACEMENT's
			// signature in place, which signs an outpoint that will never
			// exist. There is no unilateral exit for such an attempt.
			return {
				ok: false,
				error:
					'Cannot force close: confirmed funding attempt has no remote commitment signature to adopt'
			};
		}

		// The view this close is planned against: the live state, plus the
		// splice or confirmed-attempt adoption if there is one. A copy either
		// way, so that nothing below can reach the live channel by accident.
		const closing = {
			...this._state,
			...(spliceAdoption ?? {}),
			...(v2Adoption ?? {})
		} as IChannelState;

		if (!closing.fundingTxid || !closing.remoteBasepoints) {
			return { ok: false, error: 'Cannot force close: channel not funded' };
		}

		if (!closing.remoteCommitmentSignature) {
			return { ok: false, error: 'Cannot force close: no remote signature' };
		}

		// Build our latest local commitment
		const perCommitmentPoint = getPerCommitmentPoint(
			closing.localPerCommitmentSeed,
			closing.localCommitmentNumber
		);

		// Rebuild at the exact feerate the stored remote signature covers
		// (signedLocal=true) — mid-fee-round the in-flight rate can differ,
		// which would change the sighash and make the witness invalid.
		const built = buildLocalCommitment(
			closing,
			perCommitmentPoint,
			undefined,
			true
		);

		// A transaction with no outputs is consensus-invalid, so a plan built
		// around one is not a close, it is a broadcast that will be rejected.
		// The admission rules keep a channel out of that state (issues #386,
		// #388); refusing here is the backstop that turns a silent failure at
		// the network into an answer the caller can act on.
		if (built.result.tx.outs.length === 0) {
			return {
				ok: false,
				error:
					'Cannot force close: every commitment output is below the dust limit'
			};
		}

		let localNonce: Uint8Array | null = null;
		if (taproot) {
			// option_taproot: the funding output is a MuSig2 key-spend P2TR. The
			// broadcast witness is the single 64-byte BIP340 Schnorr signature
			// obtained by aggregating our partial with the peer's stored partial over
			// THIS local commitment (remoteCommitmentSignature = their 32-byte
			// partial; remoteSigningNonce = the signing nonce that accompanied it;
			// localNonce = our verification nonce for the current commitment).
			// Our verification nonce is deterministic per height, so re-derive it
			// fresh here — this reproduces the EXACT nonce the peer's stored partial
			// was made against (so the pre-reconnect commitment is force-closeable),
			// and ALWAYS re-deriving gives a fresh single-use secret-nonce
			// registration: the MuSig2 library purges a secret nonce after one
			// partialSign, so a force-close retry would otherwise find no secret.
			// Safe — same height + same persisted peer nonce + same commitment ⇒ the
			// identical signature, never a reused nonce over a different message. The
			// peer's signing nonce is persisted (remoteSigningNonce); without it we
			// cannot aggregate, which is why that is the very first thing asked.
			localNonce = this._deriveVerificationNonce(closing.localCommitmentNumber);
			closing.localNonce = localNonce;
			const aggSig = aggregateLocalCommitmentSig(
				closing,
				signer,
				localNonce,
				closing.remoteSigningNonce!,
				closing.remoteCommitmentSignature,
				perCommitmentPoint,
				closing.localCommitmentNumber
			);
			built.result.tx.setWitness(0, buildTaprootKeySpendWitness(aggSig));
		} else {
			// Create the funding witness using stored remote signature
			const funding = createFundingScript(
				closing.localBasepoints.fundingPubkey,
				closing.remoteBasepoints.fundingPubkey
			);

			// Sign our side
			const localSig = signer.signCommitmentTx(
				built.result.tx,
				funding.witnessScript,
				built.fundingAmount
			);

			// Build the 2-of-2 witness
			const witness = ChannelSigner.buildFundingWitness(
				localSig,
				closing.remoteCommitmentSignature,
				closing.localBasepoints.fundingPubkey,
				closing.remoteBasepoints.fundingPubkey,
				funding.witnessScript
			);

			built.result.tx.setWitness(0, witness);
		}

		return {
			ok: true,
			commitmentTx: built.result.tx.toBuffer(),
			spliceAdoption,
			v2Adoption,
			localNonce,
			channelId: closing.channelId!
		};
	}

	/**
	 * Commit the planned close to the live channel.
	 *
	 * Nothing here can fail. Everything that could refuse was decided in
	 * prepareForceClose, against the same candidate view this applies, so the
	 * caller is free to have made its own irreversible arrangements (a barrier
	 * queue abandoned, say) between the two calls.
	 *
	 * Apply in the same turn the plan was made. It is a decision about the
	 * state that existed when it was planned, not a standing permission: a
	 * plan held across further channel activity would commit a commitment
	 * built from a view the channel has since left.
	 */
	applyForceClosePlan(plan: IForceClosePlanReady): ChannelAction[] {
		if (plan.spliceAdoption) {
			Object.assign(this._state, plan.spliceAdoption);
			this._finishSpliceRuntime();
		}
		if (plan.v2Adoption) {
			Object.assign(this._state, plan.v2Adoption);
			// Durable proof of which attempt this close was planned against:
			// the node's close re-drive and any restart key off the confirmed
			// adopted record.
			this._state.v2InFlight!.confirmed = true;
		}
		if (plan.localNonce) {
			this._state.localNonce = plan.localNonce;
		}
		this._state.state = ChannelState.FORCE_CLOSED;

		return [
			{
				type: ChannelActionType.BROADCAST_TX,
				tx: plan.commitmentTx
			},
			{
				type: ChannelActionType.CHANNEL_CLOSED,
				channelId: plan.channelId
			}
		];
	}

	/**
	 * Initiate cooperative close by sending shutdown.
	 */
	initiateShutdown(scriptPubkey: Buffer): ChannelAction[] {
		// option_simple_close allows re-sending shutdown to update the local
		// script mid-negotiation (restarting the signing flow); legacy close
		// only permits initiating from NORMAL.
		const simpleCloseResend =
			this._state.simpleClose === true &&
			(this._state.state === ChannelState.SHUTTING_DOWN ||
				this._state.state === ChannelState.NEGOTIATING_CLOSING);
		if (this._state.state !== ChannelState.NORMAL && !simpleCloseResend) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot shutdown: wrong state'
				}
			];
		}

		// Guard against a misconfigured local close script — never broadcast a
		// shutdown whose output we could not spend.
		if (
			!isValidShutdownScript(
				scriptPubkey,
				true,
				this._state.simpleClose === true
			)
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid local shutdown scriptPubkey'
				}
			];
		}

		this._state.localShutdownScript = scriptPubkey;
		if (this._state.state === ChannelState.NORMAL) {
			this._state.state = ChannelState.SHUTTING_DOWN;
		} else {
			// Script update: abandon the in-flight closing_complete round; the
			// manager restarts negotiation with the new script.
			this.resetSimpleCloseNegotiation();
		}

		const msg: IShutdownMessage = {
			channelId: this._state.channelId!,
			scriptPubkey
		};
		if (isTaprootChannel(this._state.channelType)) {
			// Simple-taproot close: every shutdown we send starts a fresh MuSig2
			// closing session and advertises the new nonce (TLV 8).
			msg.shutdownNonce = this._refreshOurClosingNonce();
		}

		return [sendMsg(MessageType.SHUTDOWN, encodeShutdownMessage(msg))];
	}

	/**
	 * Taproot coop close: rebuild our shutdown for retransmission (reestablish).
	 * Refreshes our closing nonce — the pre-disconnect closing session is dead
	 * by construction — and re-advertises the local script. Non-taproot callers
	 * should retransmit the plain shutdown directly.
	 */
	buildShutdownRetransmit(): IShutdownMessage {
		const msg: IShutdownMessage = {
			channelId: this._state.channelId!,
			scriptPubkey: this._state.localShutdownScript ?? Buffer.alloc(0)
		};
		if (isTaprootChannel(this._state.channelType)) {
			msg.shutdownNonce = this._refreshOurClosingNonce();
			// The peer regenerates ITS closing nonce for the shutdown it must
			// retransmit after reestablish (which always arrives after this
			// runs — reestablish precedes shutdown on the wire). Drop the stale
			// one so no proposal is signed against a session the peer no longer
			// has; proposeClosingFee waits until the fresh nonce lands.
			this._remoteClosingNonce = null;
		}
		return msg;
	}

	/**
	 * Handle shutdown from remote.
	 * Per BOLT 2: upon receiving shutdown, we MUST respond with our own shutdown.
	 * @param msg - The decoded shutdown message from remote
	 * @param localScript - Optional local shutdown script (P2WPKH). If not provided,
	 *   uses previously set localShutdownScript. The ChannelManager always provides
	 *   a real script derived from the funding pubkey.
	 */
	handleShutdown(msg: IShutdownMessage, localScript?: Buffer): ChannelAction[] {
		// Lifecycle first, so the wire-visible content arms below can only ever
		// fire on a live channel: outside these states the peer may simply not
		// have seen our terminal transition yet, and a wire error here would
		// condemn a channel over a legal crossing (the standard carve-out).
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.NEGOTIATING_CLOSING
		) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected shutdown' }
			];
		}

		// Simple-taproot close: the peer's shutdown MUST carry its MuSig2
		// closing nonce (TLV 8) — without it no closing session can exist and
		// we must never fall back to ECDSA negotiation on a P2TR funding. Every
		// conformant taproot shutdown, retransmits included, carries a fresh
		// nonce (buildShutdownRetransmit always attaches one), so this is a
		// pure content check and wire-visible.
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.shutdownNonce || msg.shutdownNonce.length !== 66) {
				return this._failChannelWithWireError(
					'Taproot shutdown missing the MuSig2 closing nonce (TLV 8)'
				);
			}
		}

		// BOLT 2: reject a shutdown scriptPubkey that is not a standard spendable
		// form. Without this, a buggy/malicious peer could strand the cooperative
		// close output in an unspendable script. We accept any valid witness
		// program (incl. P2TR) so taproot peers can coop-close cleanly. OP_RETURN
		// forms are additionally allowed under option_simple_close (dust burn).
		// Wire-visible per BOLT 2's own "send an error and fail the channel"
		// option: the script forms and the simple_close negotiation are facts
		// the peer held when it sent, and a retransmit carries the persisted,
		// previously-validated script.
		if (
			!isValidShutdownScript(
				msg.scriptPubkey,
				true,
				this._state.simpleClose === true
			)
		) {
			return this._failChannelWithWireError('Invalid shutdown scriptPubkey');
		}

		// Accept shutdown in NEGOTIATING_CLOSING — peer retransmits after
		// reestablish, or (simple close) updates its script mid-negotiation,
		// which abandons our in-flight closing_complete round.
		if (this._state.state === ChannelState.NEGOTIATING_CLOSING) {
			this._state.remoteShutdownScript = msg.scriptPubkey;
			// Only adopt a fresh remote nonce (which resets the closing session)
			// when OUR nonce has also been refreshed since we last signed. The
			// legitimate case is a post-reestablish retransmit, where
			// buildShutdownRetransmit already generated a fresh local nonce (so
			// _hasSignedClosing is false). A same-connection DUPLICATE shutdown
			// arriving after we signed (_hasSignedClosing true) would otherwise
			// clear our sign-once latch while our local nonce is already spent,
			// wedging the close (partialSign throws, no secret nonce). Ignore it:
			// our already-signed partial stays valid for the peer to complete.
			if (msg.shutdownNonce && !this._hasSignedClosing) {
				this._adoptRemoteClosingNonce(msg.shutdownNonce);
			}
			if (this._state.simpleClose === true) {
				this.resetSimpleCloseNegotiation();
			}
			return [];
		}

		this._state.remoteShutdownScript = msg.scriptPubkey;
		if (msg.shutdownNonce) {
			this._adoptRemoteClosingNonce(msg.shutdownNonce);
		}

		const actions: ChannelAction[] = [];

		// If we haven't sent shutdown yet, send our shutdown response
		if (this._state.state === ChannelState.NORMAL) {
			if (localScript) {
				this._state.localShutdownScript = localScript;
			}
			if (!this._state.localShutdownScript) {
				this._state.localShutdownScript = Buffer.alloc(0);
			}
			this._state.state = ChannelState.SHUTTING_DOWN;
			// Send shutdown response per BOLT 2 (only if we have a real script)
			if (this._state.localShutdownScript.length > 0) {
				const response: IShutdownMessage = {
					channelId: this._state.channelId!,
					scriptPubkey: this._state.localShutdownScript
				};
				if (isTaprootChannel(this._state.channelType)) {
					response.shutdownNonce = this._refreshOurClosingNonce();
				}
				actions.push(
					sendMsg(MessageType.SHUTDOWN, encodeShutdownMessage(response))
				);
			}
		}

		// If no pending HTLCs, move to negotiating
		if (
			this.countPendingHtlcs(HtlcDirection.OFFERED) === 0 &&
			this.countPendingHtlcs(HtlcDirection.RECEIVED) === 0
		) {
			this._state.state = ChannelState.NEGOTIATING_CLOSING;
		}

		return actions;
	}

	/**
	 * Propose an initial closing fee (opener-side).
	 * Called after shutdown exchange when no pending HTLCs remain.
	 * Accepts either a pre-computed signature or a signing callback.
	 */
	proposeClosingFee(
		signatureOrFn: Buffer | ((feeSatoshis: bigint) => Buffer)
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot propose closing fee: wrong state'
				}
			];
		}

		// Fund-safety: the closing tx pays out localBalanceMsat/remoteBalanceMsat
		// only, so any in-flight HTLC's value would be silently burned to fees.
		// BOLT 2 forbids starting fee negotiation until all HTLCs are resolved.
		if (
			this.countPendingHtlcs(HtlcDirection.OFFERED) > 0 ||
			this.countPendingHtlcs(HtlcDirection.RECEIVED) > 0
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot propose closing fee: pending HTLCs'
				}
			];
		}

		this._state.state = ChannelState.NEGOTIATING_CLOSING;

		// Simple-taproot close: single-round negotiation. Our closing nonce
		// signs exactly ONE sighash, so we propose once (the latch is cleared
		// only by a fresh nonce exchange) and the peer must accept the fee
		// verbatim. The callback returns our 32-byte MuSig2 partial.
		if (isTaprootChannel(this._state.channelType)) {
			if (this._hasSignedClosing) {
				// Already proposed in this closing session (manager re-entry,
				// e.g. duplicate shutdown handling) — the peer has our offer.
				return [];
			}
			if (!this._remoteClosingNonce) {
				// The peer's shutdown (with its fresh nonce) has not arrived on
				// this connection yet; the proposal fires when it does.
				return [];
			}
			const idealFee = this.calculateIdealClosingFee();
			this._state.lastProposedClosingFeeSat = idealFee;
			const partial =
				typeof signatureOrFn === 'function'
					? signatureOrFn(idealFee)
					: signatureOrFn;
			this._hasSignedClosing = true;
			const taprootMsg: IClosingSignedMessage = {
				channelId: this._state.channelId!,
				feeSatoshis: idealFee,
				signature: Buffer.alloc(64),
				partialSignature: partial
			};
			return [
				sendMsg(
					MessageType.CLOSING_SIGNED,
					encodeClosingSignedMessage(taprootMsg)
				)
			];
		}

		// Calculate ideal fee from current fee rate
		const idealFee = this.calculateIdealClosingFee();
		this.initClosingFeeRange(idealFee);
		this._state.lastProposedClosingFeeSat = idealFee;

		const signature =
			typeof signatureOrFn === 'function'
				? signatureOrFn(idealFee)
				: signatureOrFn;

		const msg: IClosingSignedMessage = {
			channelId: this._state.channelId!,
			feeSatoshis: idealFee,
			signature
		};

		return [
			sendMsg(MessageType.CLOSING_SIGNED, encodeClosingSignedMessage(msg))
		];
	}

	/**
	 * Handle closing_signed from remote with fee negotiation (BOLT 2).
	 * Implements midpoint convergence: each counter-proposal moves toward
	 * the other party's last proposal. Guaranteed to converge.
	 */
	handleClosingSigned(
		msg: IClosingSignedMessage,
		signClosingFn: (feeSatoshis: bigint) => Buffer,
		verifyClosingFn?: (feeSatoshis: bigint, signature: Buffer) => boolean
	): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected closing_signed' }
			];
		}

		// Fund-safety: a peer MUST NOT send closing_signed while HTLCs are still
		// pending (BOLT 2). The closing tx is built from the settled balances only,
		// so signing here would burn any in-flight HTLC's value to miner fees.
		// Deliberately a bare local ERROR (issue 409 carve-out): a legal crossing
		// reaches it. If WE crashed and restored a snapshot lagging one removal
		// round, markForReestablish resurrects a COMMITTED entry while the peer's
		// ledger is legitimately HTLC-free, and its re-proposed closing_signed
		// lands here mid-replay. The stall also self-heals: we stay in the
		// current state (channel + funding watch intact), the replayed round
		// drains the count, and the shutdown exchange re-kicks negotiation.
		if (
			this.countPendingHtlcs(HtlcDirection.OFFERED) > 0 ||
			this.countPendingHtlcs(HtlcDirection.RECEIVED) > 0
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected closing_signed: pending HTLCs'
				}
			];
		}

		this._state.state = ChannelState.NEGOTIATING_CLOSING;
		this._state.theirLastClosingFeeSat = msg.feeSatoshis;

		// Simple-taproot close: single-round MuSig2 negotiation.
		if (isTaprootChannel(this._state.channelType)) {
			return this._handleTaprootClosingSigned(
				msg,
				signClosingFn,
				verifyClosingFn
			);
		}

		// Initialize our fee range if not done yet
		if (this._state.closingFeeMin === null) {
			const idealFee = this.calculateIdealClosingFee();
			this.initClosingFeeRange(idealFee);
		}

		// Fund-safety: never transition to CLOSED (which tears down the funding-output
		// watch upstream) on fee agreement ALONE. A peer can echo our proposed fee with
		// a garbage signature; if we closed + stopped watching we could not punish a
		// later revoked/latest commitment broadcast on the still-live funding output.
		// Verify the peer's closing signature over the agreed tx FIRST. On failure the
		// channel is failed ON THE WIRE (BOLT 2 sanctions "send an error and fail the
		// channel" here): with zero pending HTLCs both ledgers' balances agree, so a
		// conformant retransmit always verifies and a mismatch is a real divergence.
		// ERRORED keeps the funding watch alive; only CLOSED tears it down. The
		// callback is optional so existing unit callers that only exercise fee logic
		// are unaffected.
		const peerSigValid = (feeSatoshis: bigint): boolean =>
			!verifyClosingFn || verifyClosingFn(feeSatoshis, msg.signature);

		// The signature must be valid whatever we think of the fee: BOLT 2 makes
		// an invalid closing signature a MUST-fail regardless of which branch
		// the fee lands in, and checking it only at agreement let a garbage-
		// signed proposal drive the counter rounds until the final one.
		if (!peerSigValid(msg.feeSatoshis)) {
			return this._failChannelWithWireError(
				'Coop-close: peer closing signature failed to verify'
			);
		}

		// If their fee matches our last proposal → agreement reached
		if (
			this._state.lastProposedClosingFeeSat !== null &&
			msg.feeSatoshis === this._state.lastProposedClosingFeeSat
		) {
			this._state.state = ChannelState.CLOSED;
			return [
				{
					type: ChannelActionType.CHANNEL_CLOSED,
					channelId: this._state.channelId!
				}
			];
		}

		// If their fee is within our acceptable range → accept it
		if (
			msg.feeSatoshis >= this._state.closingFeeMin! &&
			msg.feeSatoshis <= this._state.closingFeeMax!
		) {
			const sig = signClosingFn(msg.feeSatoshis);
			const response: IClosingSignedMessage = {
				channelId: this._state.channelId!,
				feeSatoshis: msg.feeSatoshis,
				signature: sig
			};
			this._state.lastProposedClosingFeeSat = msg.feeSatoshis;
			this._state.state = ChannelState.CLOSED;
			return [
				sendMsg(
					MessageType.CLOSING_SIGNED,
					encodeClosingSignedMessage(response)
				),
				{
					type: ChannelActionType.CHANNEL_CLOSED,
					channelId: this._state.channelId!
				}
			];
		}

		// Counter-propose at midpoint between our last proposal and their proposal
		const ourLast =
			this._state.lastProposedClosingFeeSat ?? this.calculateIdealClosingFee();
		let counterFee = (ourLast + msg.feeSatoshis) / 2n;

		// Clamp to our acceptable range
		if (counterFee < this._state.closingFeeMin!)
			counterFee = this._state.closingFeeMin!;
		if (counterFee > this._state.closingFeeMax!)
			counterFee = this._state.closingFeeMax!;

		this._state.lastProposedClosingFeeSat = counterFee;

		const sig = signClosingFn(counterFee);
		const response: IClosingSignedMessage = {
			channelId: this._state.channelId!,
			feeSatoshis: counterFee,
			signature: sig
		};

		return [
			sendMsg(MessageType.CLOSING_SIGNED, encodeClosingSignedMessage(response))
		];
	}

	/**
	 * Taproot coop close: handle closing_signed under the single-round rule.
	 * Nonces were exchanged via shutdown (TLV 8) and each side's closing nonce
	 * signs exactly one sighash, so there is no fee haggling:
	 * - as INITIATOR (we proposed first) the peer must echo our fee exactly;
	 *   anything else is a protocol error (countering would need a second
	 *   nonce use).
	 * - as RESPONDER we accept the initiator's fee verbatim (LND behavior),
	 *   with the only sanity check being that the opener's output can pay it.
	 * The peer's 32-byte MuSig2 partial (TLV 6) is verified BEFORE any CLOSED
	 * transition — same fund-safety gate as the ECDSA path: fee agreement
	 * alone must never tear down the funding watch.
	 */
	private _handleTaprootClosingSigned(
		msg: IClosingSignedMessage,
		signClosingFn: (feeSatoshis: bigint) => Buffer,
		verifyClosingFn?: (feeSatoshis: bigint, signature: Buffer) => boolean
	): ChannelAction[] {
		if (!msg.partialSignature) {
			// Never fall back to interpreting the (zeroed) ECDSA field: the
			// funding output is P2TR key-spend and only a MuSig2 partial works.
			// Wire-visible: a pure content check no crossing can produce.
			return this._failChannelWithWireError(
				'Taproot closing_signed missing the MuSig2 partial signature (TLV 6)'
			);
		}
		if (!this._remoteClosingNonce || !this._ourClosingNonce) {
			// Deliberately bare (issue 409 carve-out), a mixed-fault arm: the
			// nonces are unpersisted privates, so a missing OUR nonce is our own
			// restart artifact, and buildShutdownRetransmit deliberately nulls
			// the remote one on reestablish. A conformant peer's mandatory
			// shutdown retransmit repopulates it (ordered transport puts that
			// shutdown before any closing_signed), so only ordering artifacts
			// and our own state land here, never provable peer divergence.
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Taproot closing_signed before the shutdown nonce exchange completed'
				}
			];
		}

		const peerSigValid = (feeSatoshis: bigint): boolean =>
			!verifyClosingFn || verifyClosingFn(feeSatoshis, msg.partialSignature!);

		// Initiator: we already made our (only) offer.
		if (this._state.lastProposedClosingFeeSat !== null) {
			if (msg.feeSatoshis !== this._state.lastProposedClosingFeeSat) {
				// Countering would need a second use of a single-use nonce, so a
				// non-echo provably cannot complete this session or any other:
				// permanent divergence, told on the wire.
				return this._failChannelWithWireError(
					`Taproot closing fee must echo our offer: sent ${this._state.lastProposedClosingFeeSat}, ` +
						`got ${msg.feeSatoshis}`
				);
			}
			if (!peerSigValid(msg.feeSatoshis)) {
				return this._failChannelWithWireError(
					'Coop-close: peer closing partial signature failed to verify'
				);
			}
			this._state.state = ChannelState.CLOSED;
			return [
				{
					type: ChannelActionType.CHANNEL_CLOSED,
					channelId: this._state.channelId!
				}
			];
		}

		// Responder: accept the initiator's first offer, but bound it to a
		// reasonable range. Single-round negotiation means we cannot counter, so
		// an unbounded accept would let the initiator burn our balance to miners
		// with an absurdly high fee (when WE are the opener, the fee comes out of
		// OUR output) or wedge the channel with an unrelayable, un-RBF-able low
		// fee. The band is computed at the EFFECTIVE channel feerate (the higher
		// of the two sides' committed rates): the initiator picks its own
		// closing feerate, which may exceed our stale local config, so a band
		// keyed only to our local feerate would reject legitimate offers.
		const bandFeeRate = BigInt(
			Math.max(
				this._state.localConfig.feeratePerKw || 253,
				this._state.remoteConfig.feeratePerKw || 253,
				253
			)
		);
		const bandLocalLen = this._state.localShutdownScript?.length ?? 22;
		const bandRemoteLen = this._state.remoteShutdownScript?.length ?? 22;
		const bandWeight = BigInt(
			206 + 4 * (9 + bandLocalLen) + 4 * (9 + bandRemoteLen) + 66
		);
		const idealFee = (bandWeight * bandFeeRate + 999n) / 1000n;
		const minAcceptableFee = idealFee / 5n;
		// The fee comes out of the OPENER's output only. When WE are the opener the
		// fee is paid from OUR balance, so bound it tightly (the legacy 2x cap) and
		// reserve our dust limit: without this an adversarial non-opener could send
		// closing_signed with feeSatoshis equal to our whole balance, the tx builder
		// would drop our sub-dust output, and the entire balance would be paid to
		// miners. When the peer is the opener the fee is theirs, so keep the lenient
		// interop band (their chosen closing feerate may exceed our stale config).
		const isOpener = this._state.role === ChannelRole.OPENER;
		const openerBalanceSat = isOpener
			? this._state.localBalanceMsat / 1000n
			: this._state.remoteBalanceMsat / 1000n;
		const maxAcceptableFee = isOpener ? idealFee * 2n : idealFee * 5n;
		if (
			msg.feeSatoshis > maxAcceptableFee ||
			msg.feeSatoshis < minAcceptableFee
		) {
			// Deliberately a BARE local refusal (issue 409 carve-out): the band
			// is derived from OUR private feerate estimate, a fact the peer
			// never held, so a conformant initiator with a fresher fee view can
			// land here on a fee the opener can perfectly well pay. A guard
			// that kills a channel must carry no known false positives; the
			// stall is recoverable (a reconnect starts a fresh closing session
			// with fresh nonces and a fresh offer). The dust and opener-balance
			// arms below stay wire-visible: those turn on the dust limit we
			// advertised at open and on the shared ledger, facts the peer held.
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Taproot closing fee ${msg.feeSatoshis} outside acceptable range [${minAcceptableFee}, ${maxAcceptableFee}]`
				}
			];
		}
		if (isOpener) {
			// Reserve our dust limit so an accepted fee can neither drop our output
			// nor consume it down to a dust remnant.
			const dust = this._state.localConfig.dustLimitSatoshis;
			if (openerBalanceSat < msg.feeSatoshis + dust) {
				return this._failChannelWithWireError(
					`Taproot closing fee ${msg.feeSatoshis} leaves our output below dust (balance ${openerBalanceSat}, dust ${dust})`
				);
			}
		} else if (msg.feeSatoshis > openerBalanceSat) {
			return this._failChannelWithWireError(
				`Taproot closing fee ${msg.feeSatoshis} exceeds opener balance ${openerBalanceSat}`
			);
		}
		if (!peerSigValid(msg.feeSatoshis)) {
			return this._failChannelWithWireError(
				'Coop-close: peer closing partial signature failed to verify'
			);
		}
		if (this._hasSignedClosing) {
			// Duplicate closing_signed in the same session — our reply is out.
			return [];
		}
		const partial = signClosingFn(msg.feeSatoshis);
		this._hasSignedClosing = true;
		this._state.lastProposedClosingFeeSat = msg.feeSatoshis;
		this._state.state = ChannelState.CLOSED;
		const response: IClosingSignedMessage = {
			channelId: this._state.channelId!,
			feeSatoshis: msg.feeSatoshis,
			signature: Buffer.alloc(64),
			partialSignature: partial
		};
		return [
			sendMsg(MessageType.CLOSING_SIGNED, encodeClosingSignedMessage(response)),
			{
				type: ChannelActionType.CHANNEL_CLOSED,
				channelId: this._state.channelId!
			}
		];
	}

	/**
	 * Inject a live on-chain feerate (sat/kw) for cooperative-close fee
	 * calculation. Anchor channels pin the COMMITMENT feerate to the 253
	 * sat/kw floor (fees ride on CPFP), so deriving the closing fee from it
	 * produces offers below the peer's minimum acceptable close fee; CLN
	 * warns ("Feerange ... below minimum acceptable") and disconnects, and
	 * the close retries forever. The effective closing feerate is the higher
	 * of this and the commitment feerate.
	 */
	setClosingFeeratePerKw(feeratePerKw: number): void {
		if (feeratePerKw > 0) this._closingFeeratePerKw = feeratePerKw;
	}

	/** Effective feerate (sat/kw) for cooperative closing transactions. */
	getClosingFeeratePerKw(): number {
		const commitmentRate = this._state.localConfig.feeratePerKw || 253;
		return Math.max(this._closingFeeratePerKw ?? 0, commitmentRate);
	}

	private calculateIdealClosingFee(): bigint {
		const feeRate = this.getClosingFeeratePerKw();
		// The fee must make the closing tx actually relayable, so use the SAME
		// weight model as the tx builder (chain/closing.ts): 2-of-2 P2WSH
		// funding input + both shutdown outputs (66-WU key-spend witness on
		// taproot). The old 170-WU shortcut priced the tx at a quarter of its
		// real weight.
		const localLen = this._state.localShutdownScript?.length ?? 22;
		const remoteLen = this._state.remoteShutdownScript?.length ?? 22;
		return calculateClosingFee(
			feeRate,
			localLen,
			remoteLen,
			isTaprootChannel(this._state.channelType)
		);
	}

	private initClosingFeeRange(idealFee: bigint): void {
		// Acceptable range: 0.5x to 2x ideal, capped at opener's available balance.
		// When WE are the opener the fee comes out of OUR output, so also reserve
		// our dust limit: a fee that pushes our output below dust would silently
		// drop it from the closing tx and burn the remainder to fees.
		const min = idealFee / 2n;
		const max = idealFee * 2n;
		const isOpener = this._state.role === ChannelRole.OPENER;
		let openerBalance = isOpener
			? this._state.localBalanceMsat / 1000n
			: this._state.remoteBalanceMsat / 1000n;
		if (isOpener) {
			const dust = this._state.localConfig.dustLimitSatoshis;
			openerBalance = openerBalance > dust ? openerBalance - dust : 0n;
		}
		this._state.closingFeeMin = min;
		this._state.closingFeeMax = max < openerBalance ? max : openerBalance;
	}

	// ─────────────── option_simple_close ───────────────

	/**
	 * Stamp the negotiation path for this closing session. Set by the manager
	 * from the init-feature intersection when shutdown starts, and re-evaluated
	 * on reestablish (features are per-connection).
	 */
	setSimpleClose(simple: boolean): void {
		// Simple-taproot channels always close via the legacy closing_signed
		// flow carrying MuSig2 partial-sig TLVs; LND excludes taproot from
		// option_simple_close/RBF close, so force the legacy path even when
		// both peers advertise feature 60.
		if (isTaprootChannel(this._state.channelType)) {
			this._state.simpleClose = false;
			return;
		}
		this._state.simpleClose = simple;
	}

	isSimpleClose(): boolean {
		return this._state.simpleClose === true;
	}

	/**
	 * Reset in-flight simple-close negotiation. Called on reestablish: the spec
	 * restarts negotiation on reconnect, so a pre-disconnect closing_complete is
	 * abandoned (its closing_sig can never arrive on the new connection).
	 */
	resetSimpleCloseNegotiation(): void {
		this._state.lastLocalClosingComplete = null;
		this._state.awaitingClosingSig = false;
	}

	/**
	 * Closer-side variant selection per BOLT 2 option_simple_close:
	 * - own post-fee output dust → only closee_output_only
	 * - closee output dust → only closer_output_only
	 * - neither dust, we are the lesser-funded side → only closer_and_closee
	 *   (the lesser-funded closer must not propose dropping the larger output)
	 * - neither dust otherwise → both closer_output_only and closer_and_closee
	 */
	private selectCloserVariants(
		feeSatoshis: bigint,
		closerScript: Buffer,
		closeeScript: Buffer
	): ClosingSigVariant[] | { error: string } {
		const ourValue = this._state.localBalanceMsat / 1000n - feeSatoshis;
		const theirValue = this._state.remoteBalanceMsat / 1000n;
		const ourDust = isDustOutput(closerScript, ourValue);
		const theirDust = isDustOutput(closeeScript, theirValue);

		if (ourDust && theirDust) {
			// Both outputs dust: the spec's OP_RETURN-burn case. We never generate
			// OP_RETURN shutdown scripts ourselves, so fail closed (a channel this
			// empty can be force-closed at negligible cost).
			return {
				error: 'Simple close: both outputs would be dust; use force-close'
			};
		}
		if (ourDust) return [ClosingSigVariant.CLOSEE_OUTPUT_ONLY];
		if (theirDust) return [ClosingSigVariant.CLOSER_OUTPUT_ONLY];
		if (this._state.localBalanceMsat < this._state.remoteBalanceMsat) {
			return [ClosingSigVariant.CLOSER_AND_CLOSEE];
		}
		return [
			ClosingSigVariant.CLOSER_OUTPUT_ONLY,
			ClosingSigVariant.CLOSER_AND_CLOSEE
		];
	}

	/**
	 * Send closing_complete (we act as the CLOSER: the fee comes entirely out of
	 * our output). Callable initially and again as an RBF bump once the previous
	 * round was answered with closing_sig.
	 */
	sendClosingComplete(
		feeSatoshis: bigint,
		locktime: number,
		signFn: (
			variant: ClosingSigVariant,
			feeSatoshis: bigint,
			locktime: number,
			closerScriptPubkey: Buffer,
			closeeScriptPubkey: Buffer
		) => Buffer
	): ChannelAction[] {
		const err = (message: string): ChannelAction[] => [
			{ type: ChannelActionType.ERROR, message }
		];

		if (
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return err('Cannot send closing_complete: wrong state');
		}
		if (
			this.countPendingHtlcs(HtlcDirection.OFFERED) > 0 ||
			this.countPendingHtlcs(HtlcDirection.RECEIVED) > 0
		) {
			return err('Cannot send closing_complete: pending HTLCs');
		}
		if (!this._state.simpleClose) {
			return err('Cannot send closing_complete: simple close not negotiated');
		}
		if (this._state.awaitingClosingSig) {
			return err(
				'Cannot send closing_complete: awaiting closing_sig for previous one'
			);
		}
		const closerScript = this._state.localShutdownScript;
		const closeeScript = this._state.remoteShutdownScript;
		if (!closerScript || closerScript.length === 0 || !closeeScript) {
			return err('Cannot send closing_complete: shutdown scripts not set');
		}
		if (feeSatoshis < 0n) {
			return err('Cannot send closing_complete: negative fee');
		}
		if (feeSatoshis > this._state.localBalanceMsat / 1000n) {
			return err('Cannot send closing_complete: fee exceeds our balance');
		}
		const prev = this._state.lastLocalClosingComplete;
		if (prev && feeSatoshis <= prev.feeSatoshis) {
			return err(
				'Cannot send closing_complete: RBF fee must increase ' +
					`(${feeSatoshis} <= ${prev.feeSatoshis})`
			);
		}

		const variants = this.selectCloserVariants(
			feeSatoshis,
			closerScript,
			closeeScript
		);
		if (!Array.isArray(variants)) {
			return err(variants.error);
		}

		const msg: IClosingCompleteMessage = {
			channelId: this._state.channelId!,
			closerScriptPubkey: closerScript,
			closeeScriptPubkey: closeeScript,
			feeSatoshis,
			locktime
		};
		for (const variant of variants) {
			const sig = signFn(
				variant,
				feeSatoshis,
				locktime,
				closerScript,
				closeeScript
			);
			if (variant === ClosingSigVariant.CLOSER_OUTPUT_ONLY) {
				msg.closerOutputOnlySig = sig;
			} else if (variant === ClosingSigVariant.CLOSEE_OUTPUT_ONLY) {
				msg.closeeOutputOnlySig = sig;
			} else {
				msg.closerAndCloseeSig = sig;
			}
		}

		this._state.state = ChannelState.NEGOTIATING_CLOSING;
		this._state.lastLocalClosingComplete = {
			feeSatoshis,
			locktime,
			closerScript,
			closeeScript,
			sentVariants: variants
		};
		this._state.awaitingClosingSig = true;

		return [
			sendMsg(MessageType.CLOSING_COMPLETE, encodeClosingCompleteMessage(msg))
		];
	}

	/**
	 * RBF entry: re-send closing_complete at a strictly higher fee. Thin guard
	 * around sendClosingComplete (which enforces monotonicity and the
	 * one-in-flight rule).
	 */
	bumpClosingFee(
		newFeeSatoshis: bigint,
		locktime: number,
		signFn: Parameters<Channel['sendClosingComplete']>[2]
	): ChannelAction[] {
		if (!this._state.lastLocalClosingComplete) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot bump closing fee: no closing_complete sent yet'
				}
			];
		}
		return this.sendClosingComplete(newFeeSatoshis, locktime, signFn);
	}

	/**
	 * Handle closing_complete from the peer (we act as the CLOSEE: the fee comes
	 * out of THEIR output; ours is untouched).
	 *
	 * Fund-safety: no CLOSED transition and no CHANNEL_CLOSED action unless the
	 * peer's signature verifies over the exact tx we would broadcast — the same
	 * posture as the legacy verifyClosingFn gate. All failures return ERROR and
	 * leave the channel (and the funding watch upstream) intact.
	 */
	handleClosingComplete(
		msg: IClosingCompleteMessage,
		verifyFn: (
			variant: ClosingSigVariant,
			feeSatoshis: bigint,
			locktime: number,
			closerScriptPubkey: Buffer,
			closeeScriptPubkey: Buffer,
			signature: Buffer
		) => boolean,
		signFn: (
			variant: ClosingSigVariant,
			feeSatoshis: bigint,
			locktime: number,
			closerScriptPubkey: Buffer,
			closeeScriptPubkey: Buffer
		) => Buffer
	): ChannelAction[] {
		const err = (message: string): ChannelAction[] => [
			{ type: ChannelActionType.ERROR, message }
		];

		// Concurrent-close race: both sides may send closing_complete. If we
		// already reached CLOSED through one direction, still co-sign the peer's
		// alternative close — both variants spend the same funding output and pay
		// us our full balance, so only one can confirm and both are fund-safe.
		// Without this, the peer would wait forever for its closing_sig.
		const alreadyClosed =
			this._state.state === ChannelState.CLOSED &&
			this._state.simpleClose === true;
		if (
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			!alreadyClosed
		) {
			return err('Unexpected closing_complete');
		}
		if (
			this.countPendingHtlcs(HtlcDirection.OFFERED) > 0 ||
			this.countPendingHtlcs(HtlcDirection.RECEIVED) > 0
		) {
			return err('Unexpected closing_complete: pending HTLCs');
		}
		if (!this._state.simpleClose) {
			return err('Unexpected closing_complete: simple close not negotiated');
		}

		// The closer pays the fee from its own (remote, from our view) balance.
		if (msg.feeSatoshis > this._state.remoteBalanceMsat / 1000n) {
			return err('closing_complete: fee exceeds closer balance');
		}
		// Their view of OUR script must match what we sent in shutdown.
		if (
			!this._state.localShutdownScript ||
			!msg.closeeScriptPubkey.equals(this._state.localShutdownScript)
		) {
			return err('closing_complete: closee script does not match ours');
		}
		// Their script may differ from their shutdown (simple close allows script
		// updates), but must still be a standard form (OP_RETURN allowed here).
		if (!isValidShutdownScript(msg.closerScriptPubkey, true, true)) {
			return err('closing_complete: invalid closer script');
		}
		this._state.remoteShutdownScript = msg.closerScriptPubkey;
		if (!alreadyClosed) {
			this._state.state = ChannelState.NEGOTIATING_CLOSING;
		}

		// Closee sig selection: own output dust → closer_output_only; otherwise
		// prefer closer_and_closee, then closee_output_only. Never sign a variant
		// that drops our non-dust output.
		const ourValue = this._state.localBalanceMsat / 1000n;
		const ourDust = isDustOutput(msg.closeeScriptPubkey, ourValue);
		let variant: ClosingSigVariant;
		let theirSig: Buffer;
		if (ourDust) {
			if (!msg.closerOutputOnlySig) {
				return err(
					'closing_complete: our output is dust but no closer_output_only sig'
				);
			}
			variant = ClosingSigVariant.CLOSER_OUTPUT_ONLY;
			theirSig = msg.closerOutputOnlySig;
		} else if (msg.closerAndCloseeSig) {
			variant = ClosingSigVariant.CLOSER_AND_CLOSEE;
			theirSig = msg.closerAndCloseeSig;
		} else if (msg.closeeOutputOnlySig) {
			variant = ClosingSigVariant.CLOSEE_OUTPUT_ONLY;
			theirSig = msg.closeeOutputOnlySig;
		} else {
			// Only closer_output_only offered but our output is not dust — signing
			// it would burn our balance to their close. Refuse.
			return err(
				'closing_complete: peer offered only closer_output_only for our non-dust output'
			);
		}

		if (
			!verifyFn(
				variant,
				msg.feeSatoshis,
				msg.locktime,
				msg.closerScriptPubkey,
				msg.closeeScriptPubkey,
				theirSig
			)
		) {
			return err('closing_complete: peer signature failed to verify');
		}

		const ourSig = signFn(
			variant,
			msg.feeSatoshis,
			msg.locktime,
			msg.closerScriptPubkey,
			msg.closeeScriptPubkey
		);
		const reply: IClosingSigMessage = {
			channelId: this._state.channelId!,
			closerScriptPubkey: msg.closerScriptPubkey,
			closeeScriptPubkey: msg.closeeScriptPubkey,
			feeSatoshis: msg.feeSatoshis,
			locktime: msg.locktime
		};
		if (variant === ClosingSigVariant.CLOSER_OUTPUT_ONLY) {
			reply.closerOutputOnlySig = ourSig;
		} else if (variant === ClosingSigVariant.CLOSEE_OUTPUT_ONLY) {
			reply.closeeOutputOnlySig = ourSig;
		} else {
			reply.closerAndCloseeSig = ourSig;
		}

		const actions: ChannelAction[] = [
			sendMsg(MessageType.CLOSING_SIG, encodeClosingSigMessage(reply))
		];
		if (!alreadyClosed) {
			this._state.state = ChannelState.CLOSED;
			actions.push({
				type: ChannelActionType.CHANNEL_CLOSED,
				channelId: this._state.channelId!
			});
		}
		return actions;
	}

	/**
	 * Handle closing_sig from the peer (we are the CLOSER). The message must
	 * echo our last closing_complete exactly and carry exactly one signature,
	 * for a variant we actually sent.
	 */
	handleClosingSig(
		msg: IClosingSigMessage,
		verifyFn: (
			variant: ClosingSigVariant,
			feeSatoshis: bigint,
			locktime: number,
			closerScriptPubkey: Buffer,
			closeeScriptPubkey: Buffer,
			signature: Buffer
		) => boolean
	): ChannelAction[] {
		const err = (message: string): ChannelAction[] => [
			{ type: ChannelActionType.ERROR, message }
		];

		// Concurrent-close race: our closing_complete may be answered after we
		// already reached CLOSED as the closee of the peer's round. Accept it —
		// broadcasting our alternative close tx is fund-safe (same funding
		// output, our balance paid in full either way).
		const alreadyClosed =
			this._state.state === ChannelState.CLOSED &&
			this._state.simpleClose === true;
		if (
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			!alreadyClosed
		) {
			return err('Unexpected closing_sig');
		}
		const last = this._state.lastLocalClosingComplete;
		if (!last || !this._state.awaitingClosingSig) {
			return err('closing_sig without a pending closing_complete');
		}
		if (
			msg.feeSatoshis !== last.feeSatoshis ||
			msg.locktime !== last.locktime ||
			!msg.closerScriptPubkey.equals(last.closerScript) ||
			!msg.closeeScriptPubkey.equals(last.closeeScript)
		) {
			return err('closing_sig does not echo our closing_complete');
		}

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
		if (sigs.length !== 1) {
			return err(
				`closing_sig must carry exactly one signature, got ${sigs.length}`
			);
		}
		const { variant, sig } = sigs[0];
		if (!last.sentVariants.includes(variant)) {
			return err('closing_sig signature variant was not offered by us');
		}

		if (
			!verifyFn(
				variant,
				msg.feeSatoshis,
				msg.locktime,
				msg.closerScriptPubkey,
				msg.closeeScriptPubkey,
				sig
			)
		) {
			return err('closing_sig: peer signature failed to verify');
		}

		this._state.awaitingClosingSig = false;
		if (alreadyClosed) {
			return [];
		}
		this._state.state = ChannelState.CLOSED;
		return [
			{
				type: ChannelActionType.CHANNEL_CLOSED,
				channelId: this._state.channelId!
			}
		];
	}

	// ─────────────── Reconnection ───────────────

	/**
	 * Mark this channel for reestablish after a peer disconnect.
	 * Saves the current state and transitions to AWAITING_REESTABLISH.
	 */
	/**
	 * Fail the channel in response to a BOLT 1 `error` from the peer. Transitions
	 * to ERRORED so we stop sending channel_reestablish for it on every reconnect:
	 * the peer has failed the channel (usually it force-closed), so re-sending
	 * reestablish just provokes another error + disconnect — a tight reconnect
	 * storm. The funding output stays watched on-chain (ERRORED is not CLOSED), so
	 * we still detect the peer's commitment and sweep our funds. Idempotent;
	 * no-op once the channel is already closed/errored. Returns true if it changed
	 * state (so the caller can persist).
	 */
	markErrored(): boolean {
		if (
			this._state.state === ChannelState.CLOSED ||
			this._state.state === ChannelState.FORCE_CLOSED ||
			this._state.state === ChannelState.ERRORED
		) {
			return false;
		}
		// A failed channel can't be mid-splice or quiescent.
		this._spliceSession?.abort('channel failed by peer error');
		this._spliceSession = null;
		this._resetSpliceDriver();
		this._pendingSplice = null;
		this._quiescence.reset();
		this._stfuReplyOwed = false;
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;
		// A BOLT 1 error landing mid-RBF-renegotiation: roll back to the
		// retained attempt before failing, exactly as a disconnect would.
		// ERRORED is force-closeable, and the renegotiation has already
		// applied its own amounts to live state while the outpoint and the
		// peer's signature still belong to the retained attempt, so a close
		// planned from here would sign a commitment the stored signature does
		// not cover. The rollback resumes an attempt-aware state, which the
		// assignment below deliberately overrides: the channel stays failed.
		this._normalizeV2AttemptForFailure();
		this._state.state = ChannelState.ERRORED;
		return true;
	}

	/**
	 * The v2 attempt repairs EVERY failure path must run before it makes the
	 * channel force-closeable. A mid-RBF stale rollback record resumes the
	 * retained attempt. A recorded-but-unsigned replacement pops back to the
	 * newest attempt that carries its own signature: the record swap
	 * re-pointed the funding outpoint at an attempt whose commitment
	 * signature never arrived while the top-level remoteCommitmentSignature
	 * still holds the previous attempt's, and prepareForceClose only checks
	 * that a signature EXISTS, so an un-normalized failure would report a
	 * successful close while broadcasting a commitment whose witness does
	 * not verify: a silent no-exit. Nothing of the abandoned replacement can
	 * reach the chain (our witnesses never left and the peer cannot complete
	 * it alone; _v2ReplacementAbandonable checks both), exactly as the
	 * reestablish and tx_abort arms argue. Shared by markErrored and
	 * _failV2SignatureStage; both override the resumed state afterwards.
	 */
	private _normalizeV2AttemptForFailure(): void {
		if (
			this._state.state === ChannelState.DUAL_FUNDING_V2 &&
			this._state.v2InFlight &&
			this._v2RecordIsStaleRollback()
		) {
			this._rollbackToRetainedV2Attempt();
		} else if (this._v2ReplacementAbandonable()) {
			this._popToPreviousV2Attempt();
		}
	}

	/**
	 * Drop the queued update_add_htlc messages no commitment_signed of ours
	 * covers, on a channel whose restore could not prove its recency (issue
	 * #469). Returns what was abandoned, so the caller can tell whoever is
	 * still waiting on it.
	 *
	 * handleReestablish replays pendingLocalUpdates as raw bytes with no
	 * inspection, which BOLT 2 requires: the peer forgets what it never
	 * committed. On a HELD channel that replay re-offers an HTLC the channel is
	 * forbidden to offer, because addHtlc refuses one outright - the on-chain
	 * deadline backstops that would enforce it are disarmed for as long as the
	 * hold stands, and the hold is permanent. Worse, the entry still carries
	 * needsCommitment, so the reestablish tail's auto-sign would COMMIT it.
	 *
	 * Only indices at or above pendingLocalUpdatesSignedCount are eligible.
	 * Everything below it is covered by our outstanding commitment_signed and
	 * MUST be replayed, and removing one would shift the boundary that count
	 * names. The entry vetoes independently: signCommitment stamps
	 * commitCoverPending and flips PENDING to COMMITTED in the same pass that
	 * sets the count, so only a PENDING entry with addRemoteCommitted false and
	 * no commitCoverPending stamp may go.
	 *
	 * Such an add is in NEITHER commitment: buildLocalCommitment excludes our
	 * offered adds while addRemoteCommitted is false, and the remote commitment
	 * only ever gets one when we sign. So dropping it desyncs no signature, and
	 * the peer's own reconnect rollback discards the uncommitted add it
	 * received - the mirror of the loop above - so both sides converge on "it
	 * never happened".
	 *
	 * localHtlcCounter is deliberately NOT rewound. Rewinding is the dangerous
	 * option: it lets a later add reuse an id a peer that kept the original
	 * still holds, which this implementation itself treats as channel-fatal.
	 * The gap it would close can never be observed, because addHtlc refuses
	 * every subsequent add on a held channel. That is why HELD-ONLY scoping is
	 * load-bearing for correctness here and not merely conservative: dropping
	 * unsigned local adds in general is a BOLT 2 deviation with nothing to
	 * justify it, since an ordinary channel replays them and the HTLC completes.
	 */
	private _dropUnsignedLocalAddsIfHeld(): IAbandonedLocalAdd[] {
		if (this._state.restoreRecencyUnproven !== true) return [];
		const queue = this._state.pendingLocalUpdates ?? [];
		const signed = this._state.pendingLocalUpdatesSignedCount;
		if (queue.length <= signed) return [];

		const kept = queue.slice(0, signed);
		const dropped: IAbandonedLocalAdd[] = [];
		for (let i = signed; i < queue.length; i++) {
			const update = queue[i];
			if (update.type !== MessageType.UPDATE_ADD_HTLC) {
				kept.push(update);
				continue;
			}
			let msg: IUpdateAddHtlcMessage;
			try {
				msg = decodeUpdateAddHtlcMessage(update.payload);
			} catch {
				// Undecodable: leave it exactly as it was rather than guess.
				kept.push(update);
				continue;
			}
			const key = `offered-${msg.id}`;
			const entry = this._state.htlcs.get(key);
			if (
				entry &&
				!(
					entry.state === HtlcState.PENDING &&
					entry.addRemoteCommitted === false &&
					entry.commitCoverPending !== true
				)
			) {
				// A signature of ours covers it: not ours to forget.
				kept.push(update);
				continue;
			}
			if (entry) {
				this._state.htlcs.delete(key);
				// The provisional debit addHtlc took comes back, the same
				// arithmetic handleRevokeAndAck applies to a terminally failed
				// offered HTLC.
				this._state.localBalanceMsat += entry.amountMsat;
			}
			dropped.push({
				htlcId: msg.id,
				paymentHash: Buffer.from(entry?.paymentHash ?? msg.paymentHash),
				amountMsat: entry?.amountMsat ?? msg.amountMsat
			});
		}
		if (dropped.length === 0) return [];
		this._state.pendingLocalUpdates = kept;
		// signedCount is untouched: nothing at or below the boundary moved.
		if (!this._owesCommitmentSignature()) {
			this._state.needsCommitment = false;
		}
		return dropped;
	}

	/**
	 * Whether anything still owes the peer a commitment_signed, mirroring every
	 * site that sets needsCommitment.
	 *
	 * Needed because autoSignAndSendCommitment gates on that flag alone, with
	 * no "would this commitment differ" test. If a dropped add was the only
	 * reason it was set, the reestablish tail would send a commitment_signed
	 * covering no updates, which BOLT 2 forbids and which CLN answers with an
	 * error - force-closing the one channel that must not be force-closed.
	 *
	 * Conservative by construction: it answers true whenever it is not certain,
	 * because a wrongly kept flag costs one redundant round while a wrongly
	 * cleared one stalls the channel until an unrelated update revives it.
	 */
	private _owesCommitmentSignature(): boolean {
		if (
			this._state.pendingLocalUpdates.length >
			this._state.pendingLocalUpdatesSignedCount
		) {
			return true;
		}
		if (
			this._state.pendingFeeratePerKw !== undefined &&
			this._state.pendingFeerateCommitted !== true
		) {
			return true;
		}
		if (
			this._state.pendingLeaseBlockheight !== undefined &&
			this._state.pendingLeaseBlockheightCommitted !== true
		) {
			return true;
		}
		// A peer update we have revoked for but not yet covered by a signature
		// of ours: handleCommitmentSigned sets the flag for exactly these, and
		// signCommitment stamps commitCoverPending when it covers them.
		for (const entry of this._state.htlcs.values()) {
			if (entry.commitCoverPending === true) continue;
			if (
				entry.addLocallyRevoked === true &&
				entry.state === HtlcState.PENDING
			) {
				return true;
			}
			if (
				entry.removalLocallyRevoked === true &&
				entry.removalRemoteCommitted !== true &&
				(entry.state === HtlcState.FULFILLED ||
					entry.state === HtlcState.FAILED)
			) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The unsigned-add rollback ALONE, for a row that is already wrapped in
	 * AWAITING_REESTABLISH (issue #469).
	 *
	 * A capsule can hold a channel persisted mid-reestablish, and
	 * markForReestablish deliberately refuses that state: re-wrapping it would
	 * overwrite `preReestablishState` with AWAITING_REESTABLISH and lose the
	 * state the channel is supposed to return to. But the drop still has to
	 * run, or handleReestablish replays an add the hold forbids the moment the
	 * peer reconnects.
	 */
	dropUnsignedHeldAdds(): IAbandonedLocalAdd[] {
		return this._dropUnsignedLocalAddsIfHeld();
	}

	markForReestablish(): IAbandonedLocalAdd[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY &&
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.SPLICING &&
			this._state.state !== ChannelState.AWAITING_TX_SIGNATURES &&
			this._state.state !== ChannelState.DUAL_FUNDING_V2
		) {
			return []; // Only mark operational, funded or resumable-open channels
		}

		// A disconnect aborts any quiescence handshake, so a splice we were waiting
		// to start can never fire. Drop it rather than leave it dangling.
		this._pendingSplice = null;

		if (
			this._state.state === ChannelState.AWAITING_TX_SIGNATURES ||
			this._state.state === ChannelState.DUAL_FUNDING_V2
		) {
			// A new connection cycle: re-arm the caller-owed release signal so
			// the next reestablish reminds the embedder while witnesses are
			// still owed (issue 307).
			this._v2CallerTxSigsSignaled = false;
			// Phase-aware, mirroring the SPLICING block below: BOLT 2's boundary
			// for a v2 open is the initial commitment_signed. Before it the open
			// is not resumable (the interactive-tx negotiation dies with the
			// connection) and in-memory channels never reach here — the
			// manager's tempChannels sweep aborts them — so the drop branch only
			// fires for rows persisted before the in-flight record existed.
			// Past it the open MUST survive: keep the session and the record so
			// handleReestablish resumes the exchange via next_funding. The peer
			// of a dropped open learns from the reestablish answer (tx_abort for
			// an unknown next_funding_txid); no proactive latch is needed
			// because nothing broadcastable ever existed for a dropped round.
			if (
				this._state.state === ChannelState.DUAL_FUNDING_V2 &&
				this._state.v2InFlight
			) {
				// An accepted replacement that no post-ack traffic ever
				// confirmed: our ack may never have arrived, or the
				// initiator may never have committed it, in which case the
				// peer still holds the PREVIOUS attempt. The retained
				// record is that attempt; roll back to it,
				// restart-equivalent (the renegotiated builder is
				// worthless, the record carries everything resumable), and
				// reestablish resumes it against a peer on either side of
				// the ack.
				this._rollbackToRetainedV2Attempt();
			}
			const keep = this._v2SentCommitment || !!this._state.v2InFlight;
			if (!keep) {
				this._state.dualFundingSession?.abort();
				this._state.dualFundingSession = null;
				this._resetV2Driver();
				this._state.v2InFlight = null;
				this._state.state = ChannelState.ERRORED;
				return [];
			}
		}

		if (this._state.state === ChannelState.SPLICING) {
			// Phase-aware: before the mid-splice commitment round the splice is not
			// resumable (interactive-tx negotiation dies with the connection) —
			// forget it; the peer learns via our reestablish omitting
			// next_funding_txid (or sends tx_abort). Once we have sent
			// commitment_signed for the splice tx (or our tx_signatures left), the
			// splice MUST survive: keep the session, the signed tx and the driver
			// flags so handleReestablish can resume per the splice spec.
			const keep = this._spliceSentCommitment || !!this._state.spliceInFlight;
			if (!keep) {
				this._spliceSession?.abort('disconnect during splice negotiation');
				this._spliceSession = null;
				this._resetSpliceDriver();
				this._state.state = this._state.preSpliceState ?? ChannelState.NORMAL;
				this._state.preSpliceState = null;
				// The peer may still hold this splice in-flight (observed with CLN:
				// it resumes the splice after reestablish and hard-errors when the
				// commitment never arrives). Tell it to forget via tx_abort before
				// our next reestablish.
				this._forgottenSplice = true;
			}
		} else {
			this._resetSpliceDriver();
		}

		// Neither a tx_abort handshake nor the reestablish-retransmit latch
		// survives a disconnect, and an un-acked tx_init_rbf dies with the
		// connection (the current attempt stayed live, so there is nothing
		// to unwind).
		this._spliceAbortPending = false;
		this._txAbortSent = false;
		this._spliceAbortIgnoreCommitment = false;
		this._reestablishRetransmitted = false;
		// Any coins selected for a raise the peer never acked go back to the
		// wallet: the request dies here, so nothing will ever spend them.
		this._releasePendingRbfTopUp();
		this._pendingRbfInit = null;
		// An un-echoed abort of a recorded attempt dies with the connection
		// too: nothing was torn down, so the attempt resumes over
		// reestablish exactly as if the abort was never sent. The rollback
		// abort's exchange dies the same way (the peer's side rolls back in
		// its own markForReestablish if the abort never arrived).
		this._v2AbortPending = false;
		this._v2RollbackAbortPending = false;

		// A partially collected start_batch is connection-scoped: the peer
		// re-announces the batch (with fresh framing) when it retransmits after
		// reestablish, and appending post-reconnect commitments to a stale
		// half-collected batch would pair signatures across two deliveries.
		this._pendingBatch = null;

		// Quiescence never survives a disconnect (BOLT 2 quiescence).
		this._quiescence.reset();
		this._stfuReplyOwed = false;
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;

		this._state.preReestablishState = this._state.state;
		this._state.state = ChannelState.AWAITING_REESTABLISH;

		// BOLT 2: uncommitted REMOTE updates do not survive a disconnect — the
		// peer forgets what it never committed via commitment_signed and
		// retransmits (possibly different) updates after reestablish. Keeping
		// them would (a) strand a phantom received-HTLC that permanently
		// debits remoteBalanceMsat and leaks an HTLC slot, and (b) make the
		// id-only add dedup swallow a reused id carrying a DIFFERENT HTLC,
		// desyncing the commitment. (Our own uncommitted updates are the
		// opposite case: they stay and replay via pendingLocalUpdates - except
		// an ADD on a held restore, which the block at the end of this method
		// drops, for the reason argued there.)
		for (const [key, entry] of this._state.htlcs) {
			// A peer add never covered by the peer's commitment_signed
			// (addLocallyRevoked flips in handleCommitmentSigned).
			if (
				key.startsWith('received-') &&
				entry.state === HtlcState.PENDING &&
				entry.addLocallyRevoked === false
			) {
				this._state.htlcs.delete(key);
				this._state.remoteBalanceMsat += entry.amountMsat;
				continue;
			}
			// A peer fulfill/fail of our offered HTLC never covered by the
			// peer's commitment_signed (removalLocallyRevoked flips there):
			// restore the HTLC; the peer retransmits the removal after
			// reestablish. (A learned preimage stays learned upstream, which
			// is harmless — it only ever lets us claim.)
			if (
				key.startsWith('offered-') &&
				(entry.state === HtlcState.FULFILLED ||
					entry.state === HtlcState.FAILED) &&
				entry.removalLocallyRevoked === false
			) {
				entry.state = HtlcState.COMMITTED;
				delete entry.removalRemoteCommitted;
				delete entry.removalLocallyRevoked;
			}
		}

		// Roll back an uncommitted fee update. A disconnect/restart may have
		// interrupted the fee-update commitment round before it finalized; without
		// this rollback we would keep building commitments at a feerate the peer
		// never committed to, permanently desyncing the commitment transactions.
		//
		// EXCEPTION: a staged fee that already reached the signable/committed
		// phase is covered by exchanged signatures and revocations — the peer
		// will NOT replay the update_fee after reconnect (it is committed on its
		// ledger), so rolling it back here is what would desync. It survives the
		// reconnect and finishes its round via the reestablish retransmissions.
		if (
			this._state.pendingFeerateSignable !== true &&
			this._state.pendingFeerateCommitted !== true
		) {
			this._state.pendingFeeratePerKw = undefined;
			// Drop the matching queued update_fee retransmission (opener): the
			// staged rate was rolled back, so replaying the update on reconnect
			// would stage a rate on the peer that we no longer track.
			this._state.pendingLocalUpdates = (
				this._state.pendingLocalUpdates ?? []
			).filter((u) => u.type !== MessageType.UPDATE_FEE);
		}

		// Roll back an uncommitted staged update_blockheight for the same
		// reason (the opener re-sends a fresh one after reconnect; a
		// signable/committed height is covered by exchanged signatures and
		// survives to finish its round).
		if (
			this._state.pendingLeaseBlockheightSignable !== true &&
			this._state.pendingLeaseBlockheightCommitted !== true
		) {
			this._state.pendingLeaseBlockheight = undefined;
		}

		// Last, after every other rollback, so the commitment-owed test sees
		// the final fee and blockheight state. Here rather than in
		// handleReestablish so it also beats the reestablish tail's auto-sign,
		// which would otherwise commit a restored unsigned add on the one
		// channel whose commitment must never move (issue #469).
		return this._dropUnsignedLocalAddsIfHeld();
	}

	/**
	 * BOLT 1 "fail the channel" for a peer protocol violation: send a wire
	 * error scoped to this channel (a conformant peer force-closes and stops
	 * using it), mark the channel ERRORED so no further updates are exchanged
	 * over provably-desynced state, persist FIRST, and surface the app-level
	 * error. Generalizes the DLP fell-behind pattern in handleReestablish.
	 *
	 * The test is DIVERGENCE, not blame. Use it for any message the peer has
	 * already put on the wire that we refuse unconditionally and permanently:
	 * from the moment we return, the peer's update log holds an entry ours
	 * never will, its next commitment_signed covers state we cannot reproduce,
	 * and the channel is dead whether or not we say so. The only choice is
	 * whether the peer learns now with the real reason, or a round later as
	 * "Invalid commitment signature" (issue 404). That covers our OWN policy
	 * refusals (dust exposure ceilings, CLTV horizons, fee bounds) as squarely
	 * as a bad signature: the peer could not have predicted the policy, but the
	 * divergence is identical.
	 *
	 * Two carve-outs, both refusals that are NOT provable divergence, and both
	 * of which keep returning plain ERROR actions:
	 *  - local API misuse by our own caller (addHtlc with a bad amount,
	 *    updateFee from the acceptor). Nothing was ever on the wire, so nothing
	 *    diverged.
	 *  - a refusal a legal in-flight crossing can produce: the lifecycle guards
	 *    (the message arrived for a channel that has since moved to
	 *    SHUTTING_DOWN, CLOSING, SPLICING or ERRORED) and the SENT_STFU half of
	 *    the quiescence guard. There the peer may be entirely conformant and
	 *    simply not yet have seen the transition we made.
	 *
	 * The crossing clause also covers the crash-replay family (issue 409): a
	 * peer restored from a legally lagging snapshot replays its whole pending
	 * update queue on reestablish (handleReestablish does the same), so the
	 * "HTLC not found" arms and the pending-HTLC closing_signed arm can fire
	 * against a conformant peer and stay bare, each argued at its guard. So
	 * does the taproot closing_signed nonce-exchange arm, whose predicate
	 * mixes our own unpersisted restart state with reestablish ordering.
	 */
	/**
	 * Fail the channel for a peer message whose payload did not even DECODE
	 * (a wrong-length TLV, a truncated field). The per-handler content checks
	 * can never see such a message, because the codec throws first and the
	 * throw used to die in ChannelManager.handleMessage's catch: no wire
	 * error, no unwind (issue 409 review). Same lifecycle carve-out as the
	 * handlers themselves: outside a live state the peer may not have seen
	 * our terminal transition, so the refusal stays local.
	 *
	 * The two pre-funding arms take the exact shapes the decoded refusals at
	 * those states use (the refuse closures in handleFundingCreated and
	 * handleFundingSigned): scoped to an id the peer can act on, with the
	 * cleanup that unwinds this stage, and deliberately WITHOUT a persisted
	 * ERRORED row, since nothing has ever been persisted in either state.
	 * They apply to ANY undecodable message resolved to a channel in these
	 * states, close messages included: no conformant peer has a shutdown or
	 * closing_signed in flight before funding_signed (there is no permanent
	 * channel_id to quote yet), and the bare-ERROR fallthrough they replace
	 * silently dropped the temp channel at SENT_ACCEPT (issue 393's shape)
	 * and left an immortal promoted registration with frozen pledges at
	 * SENT_FUNDING_CREATED (issue 412's shape).
	 *
	 * Issue 426 extends the same doctrine to the remaining negotiation
	 * states. SENT_OPEN mirrors SENT_ACCEPT exactly (the opener parked on an
	 * accept_channel it can never decode; nothing persisted, no pledges). A
	 * pre-record DUAL_FUNDING_V2 refusal is wire-visible and scoped to the id
	 * the peer keys the negotiation by; the default temp cleanup and the
	 * ERROR-arm pledge hooks unwind it. At or past the v2 signature stage
	 * (AWAITING_TX_SIGNATURES, or a recorded DUAL_FUNDING_V2 mid-RBF whose
	 * retained attempt is broadcastable) _failV2SignatureStage picks the
	 * disposition by broadcastability. Deliberately still bare: the funded
	 * pre-ready states and AWAITING_REESTABLISH (the peer's own retransmit or
	 * reconnect heals a garbled message, so the refusal is not permanent and
	 * a wire failure would kill a recoverable funded channel), SPLICING (the
	 * disconnect unwind and reestablish splice recovery resolve a wedged
	 * negotiation; the channel itself is healthy), and the dead states.
	 */
	failFromMalformedPeerMessage(reason: string): ChannelAction[] {
		if (
			this._state.state === ChannelState.SENT_ACCEPT ||
			this._state.state === ChannelState.SENT_OPEN
		) {
			return refuseWithWireError(this._state.temporaryChannelId, reason);
		}
		if (this._state.state === ChannelState.SENT_FUNDING_CREATED) {
			return refuseWithWireError(
				this._state.channelId ?? this._state.temporaryChannelId,
				reason,
				'lifecycle'
			);
		}
		if (
			this._state.state === ChannelState.DUAL_FUNDING_V2 &&
			this._state.v2InFlight == null
		) {
			return refuseWithWireError(
				this._state.channelId ?? this._state.temporaryChannelId,
				reason
			);
		}
		if (
			this._state.state === ChannelState.AWAITING_TX_SIGNATURES ||
			this._state.state === ChannelState.DUAL_FUNDING_V2
		) {
			return this._failV2SignatureStage(reason);
		}
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.NEGOTIATING_CLOSING
		) {
			return [{ type: ChannelActionType.ERROR, message: reason }];
		}
		return this._failChannelWithWireError(reason);
	}

	/**
	 * Fail a v2 open at or past the signature stage for a peer-held fault (an
	 * undecodable message, an invalid commitment signature). Wire-visible in
	 * both dispositions; broadcastability picks the cleanup.
	 *
	 * Broadcastable (witnesses left, tx fully signed, or a zero-local-input
	 * attempt): the peer may broadcast the funding tx without another byte
	 * from us, so the ERRORED row, the registration and the funding watch all
	 * survive and the pledges stay frozen. 'none' rather than the default so
	 * a not-yet-promoted attempt is never deregistered either.
	 *
	 * Not broadcastable: the decided teardown, with a BOLT 1 error in place
	 * of a tx_abort echo, since garbage is not a negotiation message we can
	 * answer in-protocol. Condemned rides the terminal persist, so the row is
	 * deletion-owed (startup deletes it instead of restoring), and the
	 * 'lifecycle' cleanup's pledge release passes hasResumableChannelRow. The
	 * record is deliberately RETAINED, unlike the recorded tx_abort teardown:
	 * the wire error's channel:errored ride runs the node's errored handler
	 * synchronously, and its non-broadcastable guard reads v2InFlight to void
	 * the channel instead of force-closing into a funding tx that can never
	 * exist. Clearing the record first blinded that guard and produced a
	 * fictional FORCE_CLOSED.
	 */
	private _failV2SignatureStage(reason: string): ChannelAction[] {
		// A failure mid-RBF must not persist or close against mixed attempt
		// state (one attempt's balances with another's outpoint and
		// signature): resume the internally consistent attempt first, the
		// same repairs markErrored runs. The broadcastability branch below
		// then reads the resumed attempt, so an abandonable replacement
		// backed by a signed previous attempt keeps its row.
		this._normalizeV2AttemptForFailure();
		if (this.isV2AttemptBroadcastable() || this.v2TeardownMustRetain()) {
			// A restored record cannot authorize the condemned teardown below
			// either: condemning deletes the row at the next start, which is
			// the same removal by a slower route (issue #463).
			return this._failChannelWithWireError(reason, 'none');
		}
		this._state.dualFundingSession?.abort();
		this._state.dualFundingSession = null;
		this._resetV2Driver();
		this._state.condemned = true;
		return this._failChannelWithWireError(reason, 'lifecycle');
	}

	private _failChannelWithWireError(
		message: string,
		cleanup?: IErrorAction['cleanup']
	): ChannelAction[] {
		// A hostile or malformed message can fail a channel whose safety
		// flags already forbid broadcasting (a restored uncertain channel
		// sent garbage counters, say). The peer-close disposition must ride
		// THIS persist too, or a crash before the error send strands the
		// channel with no reconnect chasing the peer.
		this._ensureRecoveryCloseDisposition();
		this._state.state = ChannelState.ERRORED;
		const channelId = this._state.channelId ?? this._state.temporaryChannelId;
		// Same scope rule as every other wire refusal. When the id cannot carry
		// one, the channel is still failed and persisted locally; what is lost is
		// only the peer's notification, and with it the channel:errored emit that
		// rides the send, so no close is driven until the next restart reads the
		// ERRORED row. That is the correct trade against telling a peer to fail
		// every channel it has with us.
		const wire = wireErrorFor(channelId, message);
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			...(wire ? [wire] : []),
			{
				type: ChannelActionType.ERROR,
				message,
				...(cleanup ? { cleanup } : {})
			} as IErrorAction
		];
	}

	/**
	 * Create a channel_reestablish message for reconnection.
	 */
	createReestablish(): ChannelAction[] {
		// BOLT 2: next_revocation_number is the commitment number of the next
		// revoke_and_ack we expect to RECEIVE — the count of revocations
		// received so far, NOT of commitments we signed. With a
		// commitment_signed in flight (unrevoked) the sign counter is one
		// ahead; using it here overclaimed the peer's revocations and paired
		// the claim with a secret we never received (all zeros) — CLN fails
		// the connection with "bad future last_local_per_commit_secret: N vs
		// N-1" and force-closes.
		const revocationCount = this._remoteRevocationCount();
		const lastSecret =
			revocationCount > 0n
				? this._state.shaChainStore.getSecret(
						MAX_INDEX - (revocationCount - 1n)
				  ) || Buffer.alloc(32)
				: Buffer.alloc(32);

		const myCurrentPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			this._state.localCommitmentNumber
		);

		const msg: IChannelReestablishMessage = {
			channelId: this._state.channelId!,
			nextCommitmentNumber: this._state.localCommitmentNumber + 1n,
			nextRevocationNumber: revocationCount,
			yourLastPerCommitmentSecret: lastSecret,
			myCurrentPerCommitmentPoint: myCurrentPoint
		};

		// option_taproot: our MuSig2 verification nonces are DETERMINISTIC per
		// commitment height (see _deriveVerificationNonce), so re-derive the SAME
		// nonces on reconnect rather than fresh random ones, and re-seed the peer
		// with our next-commitment verification nonce (mirrors revoke_and_ack's
		// next_local_nonce). Because the re-derived current-commitment nonce is
		// identical to the one the peer's stored partial was made against, the
		// PRE-reconnect commitment remains force-closeable after a reconnect.
		if (isTaprootChannel(this._state.channelType)) {
			this._state.localNonce = undefined;
			this._state.localNextNonce = undefined;
			this._ensureLocalFundingNonce();
			msg.nextLocalNonce = this._ensureLocalNextNonce();
		}

		// Splice resumption (merged spec): set next_funding_txid while we
		// have sent commitment_signed for an in-flight splice tx but have not yet
		// received the peer's tx_signatures. retransmit_flags bit 0 asks the peer
		// to retransmit ITS splice commitment_signed (we never received/verified
		// it).
		const nextFundingTxid = this._inFlightUnsignedSpliceTxid();
		if (nextFundingTxid) {
			msg.nextFundingTxid = nextFundingTxid;
			const haveTheirCommitment = this._state.spliceInFlight
				? this._state.spliceInFlight.remoteCommitmentSig !== null
				: this._spliceReceivedCommitment;
			msg.nextFundingRetransmitFlags = haveTheirCommitment ? 0 : 1;
		}

		// v2 open resumption (BOLT 2): set next_funding_txid while our initial
		// commitment_signed for the interactive open has left but the peer's
		// tx_signatures have not arrived; the TLV MUST be omitted once they
		// have. A channel is never mid-splice and mid-open at once, so the two
		// branches are naturally exclusive. retransmit_flags bit 0 asks the
		// peer to retransmit ITS commitment_signed (we never received it).
		if (!msg.nextFundingTxid) {
			const v2Txid = this._inFlightUnsignedV2Txid();
			if (v2Txid) {
				msg.nextFundingTxid = v2Txid;
				msg.nextFundingRetransmitFlags =
					this._state.v2InFlight?.remoteCommitmentSig != null ? 0 : 1;
			}
		}

		const actions: ChannelAction[] = [];

		// We dropped an unresumable splice; the peer may still hold it in-flight.
		// The tx_abort must go out BEFORE our channel_reestablish: CLN's channeld
		// runs every message it reads while waiting for our reestablish through
		// its tx_abort check, but once it has processed our reestablish it resumes
		// the splice and hard-errors when the splice commitment doesn't follow.
		// Sent once — on receipt CLN deletes the inflight, acks with its own
		// tx_abort and restarts channeld on the SAME connection, which then sends
		// a fresh channel_reestablish (handled as a re-reestablish upstream).
		// spliceAbortOwed is the durable form (an operator abort whose tx_abort
		// never got its echo, or never got sent at all): unlike the one-shot
		// _forgottenSplice it stays set, re-sent on every reconnect, until the
		// peer's echo settles it in handleTxAbort.
		if (
			(this._forgottenSplice || this._state.spliceAbortOwed) &&
			this._state.channelId
		) {
			this._forgottenSplice = false;
			this._spliceAbortPending = true;
			actions.push(
				this._txAbort(
					this._state.channelId,
					'splice not resumable after disconnect'
				)
			);
		}

		actions.push(
			sendMsg(
				MessageType.CHANNEL_REESTABLISH,
				encodeChannelReestablishMessage(msg)
			)
		);
		return actions;
	}

	/**
	 * True while we await the peer's tx_abort echo for a splice we told it to
	 * forget. The caller must treat a remote `error` for this channel as part of
	 * the abort exchange (CLN's channeld dies/restarts around it) rather than a
	 * channel failure.
	 */
	isSpliceAbortPending(): boolean {
		return this._spliceAbortPending;
	}

	/**
	 * Whether to answer a channel_reestablish that arrives AFTER this connection
	 * already reestablished the channel by retransmitting ours (a peer whose
	 * channel process restarted mid-connection — CLN after a tx_abort exchange —
	 * sends and expects a fresh reestablish). Latches: true at most once per
	 * connection so two retransmitting nodes can't ping-pong.
	 */
	shouldRetransmitReestablish(): boolean {
		if (this._state.state === ChannelState.AWAITING_REESTABLISH) return false;
		if (this._reestablishRetransmitted) return false;
		this._reestablishRetransmitted = true;
		return true;
	}

	/**
	 * The txid of an in-flight splice that has not yet locked (the condition
	 * for setting next_funding_txid on channel_reestablish), or null.
	 *
	 * CLN v26 semantics: BOTH sides keep announcing next_funding_txid on every
	 * reestablish until the splice tx is locked, whatever the tx_signatures
	 * state — a reestablish WITHOUT it tells the peer the splice was forgotten,
	 * and CLN then silently drops its inflight (ignoring any tx_signatures we
	 * retransmit afterwards) and carries on using the pre-splice funding.
	 * Announcing until locked keeps the inflight alive on both sides; the
	 * retransmit_flags + the peer's own next_funding drive what actually gets
	 * retransmitted.
	 */
	private _inFlightUnsignedSpliceTxid(): Buffer | null {
		const inflight = this._state.spliceInFlight;
		if (inflight) {
			const locked = inflight.localSpliceLocked && inflight.remoteSpliceLocked;
			return locked ? null : Buffer.from(inflight.spliceTxid);
		}
		const session = this._spliceSession;
		if (
			session &&
			this._spliceSentCommitment &&
			session.getState() === SpliceState.AWAITING_TX_SIGNATURES
		) {
			// The splice tx is deterministic from the negotiated session; build (or
			// reuse the cached) tx to learn its txid.
			const built = this.buildAndSignSpliceTx();
			if (built) return built.spliceTxid;
		}
		return null;
	}

	/**
	 * The txid of an in-flight v2 open whose signature exchange is incomplete
	 * (the condition for setting next_funding_txid on channel_reestablish), or
	 * null. Unlike the splice regime above (announce until locked), BOLT 2
	 * scopes the TLV for an OPEN to the tx_signatures exchange: include it
	 * while our initial commitment_signed has left and the peer's
	 * tx_signatures have not arrived, and MUST omit it once they have.
	 */
	private _inFlightUnsignedV2Txid(): Buffer | null {
		const inflight = this._state.v2InFlight;
		if (!inflight || inflight.receivedTxSignatures) return null;
		return Buffer.from(inflight.fundingTxid);
	}

	/**
	 * Splice resumption on channel_reestablish (merged splice spec):
	 * - peer's next_funding_txid matches our in-flight splice → retransmit
	 *   commitment_signed and/or tx_signatures as needed;
	 * - unknown next_funding_txid → tx_abort so the peer forgets it;
	 * - peer omits next_funding_txid while our splice is still unsigned → forget;
	 * - retransmit splice_locked (like channel_ready) if we had sent it, or send
	 *   it now if the splice tx confirmed while we were disconnected.
	 */
	private _handleReestablishSplice(
		msg: IChannelReestablishMessage
	): ChannelAction[] {
		const actions: ChannelAction[] = [];
		const inflight = this._state.spliceInFlight;
		const session = this._spliceSession;

		const ourSpliceTxid: Buffer | null = inflight
			? inflight.spliceTxid
			: this._spliceTx
			? Buffer.from(this._spliceTx.tx.getHash())
			: session?.getSpliceTxid() ?? null;

		if (msg.nextFundingTxid) {
			if (ourSpliceTxid && msg.nextFundingTxid.equals(ourSpliceTxid)) {
				// The peer is missing part of the in-flight splice exchange.
				if (!inflight?.receivedTxSignatures) {
					// Retransmit our splice commitment_signed ONLY when the peer asked
					// for it (retransmit_flags bit 0). A peer that already holds it is
					// strictly awaiting tx_signatures — CLN hard-fails on an unexpected
					// commitment_signed ("Splicing got incorrect message from peer:
					// WIRE_COMMITMENT_SIGNED (should be WIRE_TX_SIGNATURES)"). Legacy
					// peers (no flags byte) can't tell us, so resend to be safe.
					const peerWantsCommitment =
						msg.nextFundingRetransmitFlags === undefined ||
						(msg.nextFundingRetransmitFlags & 1) === 1;
					if (peerWantsCommitment) {
						this._spliceSentCommitment = false;
						actions.push(...this._maybeSendSpliceCommitment());
					}
					if (this._spliceReceivedCommitment) {
						if (inflight?.sentTxSignatures) {
							// Already past the point of no return: resend the recorded sigs.
							actions.push(...this._retransmitSpliceTxSignatures());
						} else {
							this._spliceSentTxSigs = false;
							actions.push(...this._maybeSendSpliceTxSigsOrdered());
						}
					}
				} else {
					// We are fully signed; the peer only needs our tx_signatures again.
					actions.push(...this._retransmitSpliceTxSignatures());
				}
			} else if (this._state.channelId) {
				// We never signed a splice with this txid — tell the peer to forget it.
				this._spliceAbortPending = true;
				actions.push(
					this._txAbort(this._state.channelId, 'unknown next_funding_txid')
				);
			}
		} else if (
			inflight
				? !inflight.sentTxSignatures && !inflight.receivedTxSignatures
				: session && !session.isComplete()
		) {
			// The peer reestablished without next_funding_txid while our splice is
			// still unsigned (no tx_signatures in either direction — an in-flight
			// record may already exist from the commitment round): the peer has
			// forgotten the splice — forget ours too.
			const hadRecord = !!this._state.spliceInFlight;
			const abortActions = this.abortSplice(
				'peer reestablished without next_funding_txid'
			);
			actions.push(
				...abortActions.filter((a) => a.type !== ChannelActionType.ERROR)
			);
			// A record meant the splice was persisted at the commitment round:
			// persist the unwind, or a crash would resurrect the forgotten
			// splice via restoreSpliceInFlight (issue #356). handleReestablish
			// only prepends a persist when the batch carries a send, and this
			// arm can produce none. Redundant with that prepend when sends
			// exist; the manager commits once per batch.
			if (hadRecord && !this._state.spliceInFlight) {
				actions.push({ type: ChannelActionType.PERSIST_STATE });
			}
		}

		// ── splice_locked retransmission (analogous to channel_ready) ──
		if (this._state.state === ChannelState.SPLICING && this._state.channelId) {
			if (
				(inflight?.localSpliceLocked || session?.hasSentSpliceLocked()) &&
				ourSpliceTxid
			) {
				actions.push(
					sendMsg(
						MessageType.SPLICE_LOCKED,
						encodeSpliceLockedMessage({
							channelId: this._state.channelId,
							fundingTxid: ourSpliceTxid
						})
					)
				);
			} else if (inflight?.confirmed && inflight.receivedTxSignatures) {
				// The splice tx confirmed while we were disconnected: lock it now.
				actions.push(...this.sendSpliceLocked());
			}
		}

		return actions;
	}

	/**
	 * Re-send our v2 open tx_signatures verbatim from the in-flight record,
	 * without re-signing (no shared input exists for an open, so the message
	 * carries only the wallet witnesses). Only valid once they left the first
	 * time — the release gates of _maybeSendV2TxSigs stay authoritative.
	 */
	private _retransmitV2TxSignatures(): ChannelAction[] {
		const inflight = this._state.v2InFlight;
		if (!inflight?.sentTxSignatures || !this._state.channelId) return [];
		return [
			sendMsg(
				MessageType.TX_SIGNATURES,
				encodeTxSignaturesMessage({
					channelId: this._state.channelId,
					txid: inflight.fundingTxid,
					witnesses: inflight.ourWitnesses
				})
			)
		];
	}

	/**
	 * Whether reestablish handling should route next_funding through the v2
	 * OPEN resumption rather than the splice one: a v2 channel whose opening
	 * exchange may still owe the peer something, with either the durable
	 * record or a live session. A side that signed second advances to
	 * AWAITING_FUNDING_CONFIRMED (zero-conf: AWAITING_CHANNEL_READY) the
	 * moment it is fully signed, while the peer may still LACK our
	 * tx_signatures; the record is retained until NORMAL exactly so the
	 * peer's next_funding is answered with a verbatim replay here instead of
	 * the splice handler's tx_abort. NORMAL never qualifies (the record is
	 * cleared when both channel_readys crossed, and a stale one must not
	 * re-enter here).
	 */
	private _v2OpenResuming(): boolean {
		if (this._state.fundingVersion !== 2) return false;
		if (this._spliceSession || this._state.spliceInFlight) return false;
		switch (this._state.state) {
			case ChannelState.AWAITING_TX_SIGNATURES:
			case ChannelState.DUAL_FUNDING_V2:
				return !!this._state.v2InFlight || !!this._state.dualFundingSession;
			case ChannelState.AWAITING_FUNDING_CONFIRMED:
			case ChannelState.AWAITING_CHANNEL_READY:
				return !!this._state.v2InFlight;
			default:
				return false;
		}
	}

	/**
	 * v2 open resumption on channel_reestablish (BOLT 2 interactive-tx
	 * establishment):
	 * - peer's next_funding_txid matches our in-flight open → retransmit our
	 *   commitment_signed when asked (retransmit_flags bit 0, a legacy peer
	 *   with no flags byte, or a pre-#1289 peer's next_commitment_number 0),
	 *   then tx_signatures per the ordering rules;
	 * - the txids disagree while we hold an in-flight open → wire error and
	 *   fail (BOLT 2: neither side can prove which negotiation the other's
	 *   signatures cover), never tx_abort once our tx_signatures left;
	 * - peer's txid with nothing in flight on our side → tx_abort so it can
	 *   forget the round;
	 * - peer omitted next_funding while nothing irreversible crossed → the
	 *   peer forgot the open: unwind ours, tx_abort tells it we did too.
	 */
	private _handleReestablishV2(
		msg: IChannelReestablishMessage
	): ChannelAction[] {
		const actions: ChannelAction[] = [];
		const inflight = this._state.v2InFlight;

		if (msg.nextFundingTxid) {
			if (inflight && msg.nextFundingTxid.equals(inflight.fundingTxid)) {
				if (!inflight.receivedTxSignatures) {
					const peerWantsCommitment =
						msg.nextFundingRetransmitFlags === undefined ||
						(msg.nextFundingRetransmitFlags & 1) === 1 ||
						msg.nextCommitmentNumber === 0n;
					if (peerWantsCommitment) {
						// Re-sign commitment #0 byte-identically (RFC 6979 over
						// the same funding outpoint and per-commitment point;
						// taproot cannot appear here). This is also the release
						// of a commitment we OWED: a crash between the persist
						// that recorded the peer's commitment_signed and our own
						// send leaves the peer asking for a signature that never
						// left, and BOLT 2 numbers alone would never resend it.
						this._v2SentCommitment = false;
						actions.push(...this._maybeSendV2Commitment());
					}
					if (this._v2ReceivedCommitment) {
						if (inflight.sentTxSignatures) {
							// Past the point of no return: replay the recorded
							// witnesses, never re-sign.
							actions.push(...this._retransmitV2TxSignatures());
						} else {
							this._v2TxSigsReleased = false;
							actions.push(...this._maybeSendV2TxSigs());
						}
					}
				} else {
					// We are fully signed; the peer only needs our tx_signatures.
					actions.push(...this._retransmitV2TxSignatures());
				}
			} else if (inflight && this._inFlightUnsignedV2Txid()) {
				// BOTH sides advertised next_funding and the values disagree
				// (e.g. divergent RBF attempts): BOLT 2 reserves the hard
				// failure for exactly this case, since neither side can prove
				// which negotiation the other's signatures cover.
				return this._failChannelWithWireError(
					'channel_reestablish next_funding_txid does not match the in-flight v2 open'
				);
			} else if (this._state.channelId) {
				// We did not advertise: we are fully signed (our reestablish
				// correctly omits the TLV once the peer's tx_signatures were
				// received), or a live session never reached its commitment
				// round. Either way BOLT 2 answers the peer's unknown
				// next_funding_txid with tx_abort so it can forget THAT
				// negotiation; nothing of ours unwinds.
				actions.push(
					this._txAbort(this._state.channelId, 'unknown next_funding_txid')
				);
			}
		} else if (this._v2ReplacementAbandonable()) {
			// The peer reestablished without next_funding while our UNSIGNED
			// replacement still points at it: the peer never committed the
			// replacement (a disconnect between the ack and its commitment
			// rolls it back on its side), so the newest superseded attempt is
			// the shared truth. Resume it; nothing of the replacement can
			// appear on chain (our witnesses never left, and the peer cannot
			// complete it alone). No abort is owed: the peer holds nothing of
			// the replacement to forget.
			this._popToPreviousV2Attempt();
			actions.push({ type: ChannelActionType.PERSIST_STATE });
		} else if (
			inflight &&
			!inflight.sentTxSignatures &&
			!inflight.receivedTxSignatures &&
			!this.isV2AttemptBroadcastable()
		) {
			// The peer reestablished without next_funding while no tx_signatures
			// crossed in either direction: it has forgotten the open (BOLT 2
			// lets it, before its commitment_signed left). Unwind ours; the
			// tx_abort converges a peer that merely lagged. With sentTxSignatures
			// set, omission is instead EXPECTED (the peer received our
			// signatures and MUST NOT set the TLV) and nothing happens. A
			// BROADCASTABLE attempt (the zero-local-input case: the peer needs
			// no witness bytes from us and already holds our commitment
			// signature) is never unwound on omission: the peer saying it
			// forgot does not stop it, or anyone who saw the tx, from
			// publishing, so the record and the watch stay.
			this._state.dualFundingSession?.abort();
			this._state.dualFundingSession = null;
			this._resetV2Driver();
			this._state.v2InFlight = null;
			this._state.state = ChannelState.ERRORED;
			if (this._state.channelId) {
				actions.push(
					this._txAbort(
						this._state.channelId,
						'peer reestablished without next_funding_txid'
					)
				);
			}
		}

		// A confirmation parked while the channel could not consume it (the
		// depth callback is one-shot) flushes on ANY reestablish once the
		// exchange is complete: after both sides hold tx_signatures, BOTH
		// reestablish messages correctly omit next_funding, so none of the
		// arms above runs for it. Re-read the record, since the omission arm
		// may have unwound it.
		const record = this._state.v2InFlight;
		if (record?.confirmed && record.receivedTxSignatures) {
			actions.push(...this.fundingConfirmed(Buffer.from(record.fundingTxid)));
		} else {
			// A SUPERSEDED attempt's parked confirmation (stamped while
			// disconnected): adopt it now, same one-shot rationale.
			const confirmedPrevious = this._state.v2PreviousAttempts?.find(
				(rec) => rec.confirmed
			);
			if (confirmedPrevious) {
				actions.push(
					...this.fundingConfirmed(Buffer.from(confirmedPrevious.fundingTxid))
				);
			}
		}

		return actions;
	}

	/**
	 * Re-send our splice tx_signatures from the recorded in-flight splice (or the
	 * cached splice tx), without re-signing.
	 */
	private _retransmitSpliceTxSignatures(): ChannelAction[] {
		if (!this._state.channelId) return [];
		const inflight = this._state.spliceInFlight;
		if (inflight) {
			return [
				sendMsg(
					MessageType.TX_SIGNATURES,
					encodeTxSignaturesMessage({
						channelId: this._state.channelId,
						txid: inflight.spliceTxid,
						witnesses: inflight.ourWalletWitnesses,
						sharedInputSignature: inflight.ourSharedInputSig
					})
				)
			];
		}
		if (this._spliceTx) {
			return [
				sendMsg(
					MessageType.TX_SIGNATURES,
					encodeTxSignaturesMessage({
						channelId: this._state.channelId,
						txid: Buffer.from(this._spliceTx.tx.getHash()),
						witnesses: this._spliceTx.ourWalletWitnesses,
						sharedInputSignature: this._spliceTx.localSig
					})
				)
			];
		}
		return [];
	}

	/**
	 * Rebuild the in-memory splice session/driver from a persisted in-flight
	 * splice (state.spliceInFlight) after a restart. Call before
	 * markForReestablish() so the splice survives the reconnect handling.
	 */
	restoreSpliceInFlight(): void {
		const inflight = this._state.spliceInFlight;
		if (!inflight || this._spliceSession) return;
		if (
			!this._state.channelId ||
			!this._state.remoteBasepoints ||
			!this._state.fundingTxid
		)
			return;
		const tx = bitcoin.Transaction.fromHex(inflight.spliceTxHex);
		const oldFunding = createFundingScript(
			this._state.localBasepoints.fundingPubkey,
			this._state.remoteBasepoints.fundingPubkey
		);
		const sharedInputIndex = findInputIndex(
			tx,
			this._state.fundingTxid,
			this._state.fundingOutputIndex
		);
		if (sharedInputIndex < 0) return;

		this._spliceTx = {
			tx,
			sharedInputIndex,
			newFundingOutputIndex: inflight.newFundingOutputIndex,
			oldWitnessScript: oldFunding.witnessScript,
			localSig: inflight.ourSharedInputSig,
			ourWalletWitnesses: inflight.ourWalletWitnesses,
			ourWalletInputIndices: inflight.ourWalletInputIndices
		};
		this._spliceSession = SpliceSession.restore({
			channelId: this._state.channelId,
			localFundingPubkey: this._state.localBasepoints.fundingPubkey,
			remoteFundingPubkey: inflight.remoteFundingPubkey,
			isInitiator: inflight.isInitiator,
			localRelativeSatoshis: inflight.localRelativeSatoshis,
			remoteRelativeSatoshis: inflight.remoteRelativeSatoshis,
			fundingFeeratePerkw: this._state.commitmentFeeratePerkw || 253,
			spliceTxid: inflight.spliceTxid,
			spliceFundingOutputIndex: inflight.newFundingOutputIndex,
			receivedTxSignatures: inflight.receivedTxSignatures,
			localSpliceLocked: inflight.localSpliceLocked,
			remoteSpliceLocked: inflight.remoteSpliceLocked
		});
		// An in-flight splice only exists once the mid-splice commitment round
		// completed (or our sigs left), so both commitment flags are true.
		this._spliceSentCommitment = true;
		this._spliceReceivedCommitment = true;
		this._spliceSentTxSigs = inflight.sentTxSignatures;
		this._spliceRemoteCommitmentSig = inflight.remoteCommitmentSig;
		this._spliceRemoteHtlcSigs = inflight.remoteHtlcSignatures ?? null;
	}

	/**
	 * Rebuild the in-memory v2 opening session/driver from the persisted
	 * in-flight record (state.v2InFlight) after a restart. Call before
	 * markForReestablish() so the open survives the reconnect handling. The
	 * rebuilt session is builder-less: the negotiated funding tx and our
	 * witnesses come from the record, never from re-signing.
	 */
	restoreV2InFlight(): void {
		const inflight = this._state.v2InFlight;
		if (!inflight || this._state.dualFundingSession) return;
		if (!this._state.channelId || !this._state.remoteBasepoints) return;
		// Taproot v2 opens fail closed before any signature, so a taproot
		// record cannot exist; refuse to resume one rather than resume into a
		// MuSig2 exchange that does not exist.
		if (isTaprootChannel(this._state.channelType)) return;

		this._state.dualFundingSession = DualFundingSession.restore({
			channelId: this._state.channelId,
			isInitiator: inflight.isInitiator,
			remoteContributionSats: inflight.remoteContributionSats,
			fundingTxid: inflight.fundingTxid,
			fundingOutputIndex: inflight.fundingOutputIndex,
			ourWitnesses: inflight.sentTxSignatures
				? inflight.ourWitnesses.map((w) => w.map((b) => Buffer.from(b)))
				: null,
			receivedTxSignatures: inflight.receivedTxSignatures,
			rbfCount: inflight.rbfAttempt
		});
		// The record only exists once our initial commitment_signed left (or
		// was owed against the persist that recorded the peer's).
		this._v2SentCommitment = true;
		this._v2ReceivedCommitment = inflight.remoteCommitmentSig !== null;
		this._v2TxSigsReleased = inflight.sentTxSignatures;
		// Defensive: the commitment round set these before the first persist.
		if (!this._state.fundingTxid) {
			this._state.fundingTxid = Buffer.from(inflight.fundingTxid);
			this._state.fundingOutputIndex = inflight.fundingOutputIndex;
		}
		// Unconditional, unlike the outpoint above: whenever this runs the
		// record IS the active attempt, and the row's top-level amounts can be
		// a LATER attempt's. A contribution change is applied to live state
		// when the renegotiation is accepted, one persist before the
		// replacement records itself, so a crash in that window leaves the
		// replacement's capacity and balances on a row that rolls back to this
		// record. Restoring here re-pairs the amounts with the attempt for
		// every caller: startup restore, the open-abandon revert, the live
		// resync, and the in-memory rollbacks that call this right after
		// _activateV2Record targeted the same record (idempotent).
		this._restoreV2RecordSnapshot(inflight);
	}

	/**
	 * Lower the enforced channel reserve of a row that is carrying more than its
	 * capacity prices (issue #381), on load.
	 *
	 * A row written before the open sites recorded what they advertised carries
	 * the configured static reserve, a flat 10,000 by default, for the life of the
	 * channel: localConfig is persisted per channel and nothing re-derives it.
	 * Under 1,000,000 sat that refuses HTLCs the peer is entitled to send, and the
	 * refusal is a bare ERROR the peer never sees, so its next commitment_signed
	 * covers an HTLC we do not hold and the channel force closes. The fix at the
	 * open sites cannot reach a channel that is already open, so without this the
	 * change repairs nothing that exists. A v2 row written before #383 derived
	 * either reserve is the same shape (issue #387).
	 *
	 * It runs ONLY on a row with no channelReserveVersion, i.e. one whose reserve
	 * no site ever wrote. Every site that establishes the value stamps the
	 * version, so a channel that negotiated its reserve keeps that exact number
	 * across restarts and this never sees it. The re-derivation is deliberately
	 * the weakest reserve any build could have advertised at the row's capacity,
	 * which is the right answer for an unmarked row and the wrong one for a
	 * marked row, so the marker is what separates them rather than arithmetic.
	 *
	 * Two further properties make it safe rather than a second guess at what the
	 * channel negotiated:
	 *
	 * - It only ever LOWERS. The enforced reserve is read at three places
	 *   (handleUpdateAddHtlc, handleUpdateFee, and IChannelInfo reporting) and a
	 *   smaller value is strictly more permissive at all of them, so this can stop
	 *   us refusing traffic the peer believes is legal and can never start
	 *   refusing anything. That asymmetry is also why a legacy row above
	 *   1,000,000 sat, which under-enforces, is left alone rather than raised: if
	 *   the re-derivation were wrong for even one row, raising it opens a refusal
	 *   band and force closes that channel.
	 * - reserveWeEnforceAt reads only fields this method never writes, so
	 *   `stored := min(stored, derived)` is a fixed point after one application
	 *   and needs no marker to run once. That matters, because a channel row has
	 *   no schema version to hang a marker on, and the previous gate, "the value
	 *   is still the node's configured one", silently skipped every row whose
	 *   operator had changed that configuration since the channel opened.
	 *   Composing with a splice is safe for the same reason: the adoption tail
	 *   takes the same min against the same function of the same capacity.
	 *
	 * A v2 open still negotiating is left to _restoreV2RecordSnapshot, which
	 * restoreChannel runs immediately before this and which owns both reserves
	 * for the active attempt. Nothing is lost by waiting: such a row is not yet
	 * NORMAL, so it admits no HTLC to over-enforce against, and the repair lands
	 * at the next load once channel_ready nulls the record.
	 */
	repairEnforcedChannelReserve(): void {
		// A row whose reserve was WRITTEN by a site that knew what the channel
		// negotiated keeps it, exactly. The re-derivation below cannot reproduce
		// such a value and is not meant to: it is the weakest reserve any build
		// could have advertised at this capacity, which is the right answer only
		// while the row's provenance is unknown. Applied to a modern v1 acceptor
		// row it would drop a negotiated 1,000 to 546 and hand a faulty or
		// hostile peer 454 sats of room BOLT 2 makes us responsible for refusing.
		if (this._state.channelReserveVersion) return;
		if (this._state.fundingSatoshis <= 0n) return;
		if (this._state.v2InFlight || this._state.v2PreviousAttempts?.length) {
			return;
		}
		const derived = reserveWeEnforceAt(
			this._state,
			this._state.fundingSatoshis
		);
		if (derived >= this._state.localConfig.channelReserveSatoshis) return;
		this._state.localConfig = {
			...this._state.localConfig,
			channelReserveSatoshis: derived
		};
	}

	/**
	 * Raise the reserve a v2 or spliced row KEEPS for itself to what its
	 * capacity prices, on load (issues #387, #382).
	 *
	 * The mirror of repairEnforcedChannelReserve, in the opposite direction and
	 * for the opposite reason. remoteConfig.channelReserveSatoshis is what the
	 * PEER requires of US, and a v2 channel never puts it on the wire: both
	 * sides derive it, so a row written before #383 derived anything carries the
	 * node's configured constant instead. Above 1,000,000 sat that constant is
	 * BELOW what the peer derives, and the first HTLC that crosses into the gap
	 * is one the peer MUST refuse, which fails the channel.
	 *
	 * So this only ever RAISES, exactly as its neighbour only ever lowers. Both
	 * move in their own safe direction: over-enforcing on the peer force closes,
	 * and so does under-keeping for ourselves. Keeping more than we must costs
	 * getSpendableOutboundMsat and nothing else, and it is also why a stored
	 * value ABOVE the derivation is left alone rather than normalized down; the
	 * one visible cost is that as the opener of a small legacy row our own
	 * updateFee can now self-refuse against the larger reserve.
	 *
	 * v2 rows and SPLICED rows, the same branch rule as reserveWeEnforceAt. An
	 * unspliced v1 reserve was negotiated on the wire and stored verbatim, so
	 * there is nothing to re-derive and no ambiguity to resolve. A spliced row
	 * of either version is different (issue #382): eclair re-derives both
	 * reserves from the new capacity once fundingTxIndex > 0, v1 included, so
	 * after a splice-in the peer may be enforcing more against us than the row
	 * kept. The splice adoption tail now raises the kept reserve at every
	 * adoption; this covers rows whose splice adopted BEFORE that existed. And
	 * v2ReserveWeKeep is at or above what eclair (max(1%, a dust limit)) and
	 * CLN (max(1%, the opener's dust limit)) each require of us at any dust
	 * pairing and any splice history (CLN never re-prices across a splice, so
	 * what it enforces is bounded by the max() this composes with), so raising
	 * to it can never overshoot a conforming peer.
	 *
	 * Not gated on channelReserveVersion: that stamp records the provenance of
	 * the reserve we ENFORCE, negotiated versus never written, which says
	 * nothing about a value both peers derive. It needs no marker anyway, since
	 * v2ReserveWeKeep reads only fields this never writes, so
	 * `stored := max(stored, derived)` is a fixed point after one application. A
	 * still-negotiating row is left to _restoreV2RecordSnapshot, which owns both
	 * reserves for the active attempt.
	 */
	repairKeptChannelReserve(): void {
		if (this._state.fundingVersion !== 2 && !this._state.spliceFundingTxid) {
			return;
		}
		if (this._state.fundingSatoshis <= 0n) return;
		if (this._state.v2InFlight || this._state.v2PreviousAttempts?.length) {
			return;
		}
		const derived = v2ReserveWeKeep(
			this._state.fundingSatoshis,
			this._state.localConfig.dustLimitSatoshis,
			this._state.remoteConfig.dustLimitSatoshis
		);
		if (derived <= this._state.remoteConfig.channelReserveSatoshis) return;
		this._state.remoteConfig = {
			...this._state.remoteConfig,
			channelReserveSatoshis: derived
		};
	}

	/**
	 * Refuse to resume a restored v2 open whose commitment #0 could never be
	 * broadcast, on load. Returns whether it tore one down (issue #387).
	 *
	 * restoreV2InFlight rebuilds the session for any record past our initial
	 * commitment_signed and asks nothing about the split it is resuming. Every
	 * attempt negotiated since #383 was admitted by _v2InitialCommitmentRefusal,
	 * so the only records this can fire on are older ones: a signed-but-unfunded
	 * open whose commitment has no outputs would, if resumed, put a funding
	 * output on chain that neither side can ever spend.
	 *
	 * Narrow on purpose, in two directions.
	 *
	 * It runs only from ChannelManager.restoreChannel, never inside
	 * restoreV2InFlight, because that method is also the rollback and adoption
	 * path: _rollbackToRetainedV2Attempt runs from markForReestablish on EVERY
	 * disconnect, and _v2AdoptPreviousAttempt runs on an attempt that has
	 * already reached confirmation depth. Erroring a channel from either would
	 * be a far worse failure than the one this prevents.
	 *
	 * And it only disposes of an attempt NOBODY can still publish, the same test
	 * handleReestablish applies before unwinding on a missing next_funding: no
	 * tx_signatures crossed in either direction, and the transaction still needs
	 * witness bytes from us. That question is asked of the CURRENT record
	 * (_v2RecordBroadcastable), never of the channel: isV2AttemptBroadcastable
	 * answers true while ANY retained attempt is publishable, so asking it here
	 * would let a broadcastable previous attempt wave an unsigned, outputless
	 * replacement through to resume and release its tx_signatures. A
	 * broadcastable CURRENT record (the zero-local-input acceptor, the commonest
	 * shape of all) is left alone, because dropping it would not stop the peer
	 * publishing, it would only discard what _computeV2ConfirmedAdoption needs
	 * to adopt the channel afterwards and retire our own rebroadcast obligation.
	 *
	 * Disposal is a ROLLBACK wherever there is something to roll back to. An
	 * unviable replacement with retained attempts behind it is exactly
	 * _v2ReplacementAbandonable, the shape a peer may legally tell us to forget,
	 * so it is abandoned in favour of the newest superseded attempt rather than
	 * condemning a channel whose previous candidate may still confirm. The loop
	 * repeats because the resumed attempt gets the same question, and terminates
	 * because every pass shortens v2PreviousAttempts. No tx_abort is owed for
	 * the same reason the reestablish arm owes none: the peer holds nothing of
	 * an unsigned replacement to forget.
	 *
	 * Only when nothing is left to fall back to is the open condemned, and the
	 * teardown is then markForReestablish's, so it ends in exactly the state a
	 * non-resumable open does. ERRORED is also what stops the funding
	 * rebroadcast: retryPendingFundingBroadcasts retires any pending transaction
	 * whose channel is in a dead state. The caller is expected to persist the
	 * result; ChannelManager.restoreChannel reports it so the node can, since an
	 * in-memory-only disposal would be undone by the next restart.
	 */
	refuseUnviableV2InFlight(): 'none' | 'rolled-back' | 'refused' {
		let rolledBack = false;
		for (;;) {
			const record = this._state.v2InFlight;
			if (!record) return rolledBack ? 'rolled-back' : 'none';
			if (
				record.sentTxSignatures ||
				record.receivedTxSignatures ||
				this._v2RecordBroadcastable(record)
			) {
				return rolledBack ? 'rolled-back' : 'none';
			}
			// Post-snapshot: restoreChannel calls this after restoreV2InFlight,
			// and _popToPreviousV2Attempt re-runs it, so live state always
			// carries THIS attempt's amounts whichever record shape it is.
			const viability = this._v2InitialCommitmentRefusal(
				this._state.localBalanceMsat / 1000n,
				this._state.remoteBalanceMsat / 1000n,
				record.isInitiator
			);
			if (!viability) return rolledBack ? 'rolled-back' : 'none';
			if (this._v2ReplacementAbandonable()) {
				this._popToPreviousV2Attempt();
				rolledBack = true;
				continue;
			}
			this._state.dualFundingSession?.abort();
			this._state.dualFundingSession = null;
			this._resetV2Driver();
			this._state.v2InFlight = null;
			this._state.state = ChannelState.ERRORED;
			return 'refused';
		}
	}

	/**
	 * Record that the splice tx reached confirmation depth while splice_locked
	 * could not be sent (e.g. the channel was AWAITING_REESTABLISH). The lock is
	 * flushed by handleReestablish on the next reconnect.
	 */
	markSpliceConfirmed(): void {
		if (this._state.spliceInFlight) {
			this._state.spliceInFlight.confirmed = true;
		}
	}

	/**
	 * Handle channel_reestablish from remote (BOLT 2 §5).
	 *
	 * Full logic:
	 * - Validates data_loss_protect fields (yourLastPerCommitmentSecret)
	 * - Retransmits lost commitment_signed if peer missed it
	 * - Retransmits lost revoke_and_ack if peer missed it
	 * - Restores pre-reestablish state on success
	 * - Force closes on irrecoverable state gaps
	 */
	handleReestablish(msg: IChannelReestablishMessage): ChannelAction[] {
		const actions: ChannelAction[] = [];
		// A fresh exchange begins; the previous session's outcome is stale.
		this._lastReestablishOutcome = null;

		// BOLT 2: next_commitment_number MUST NOT be 0 — the initial commitment
		// (number 0) is delivered inside funding_created/funding_signed, so the
		// first commitment_signed a peer can expect is number 1. Zero means the
		// peer's state is corrupt or hostile; fail the channel loudly rather
		// than fall through the retransmission logic with it. One exception:
		// pre-#1289 dual-funding peers (eclair 0.13.x) signal a missing initial
		// commitment_signed for an interactive OPEN with next_commitment_number
		// 0 beside next_funding, instead of the retransmit flag; the matching
		// txid proves that context, and the v2 resumption below treats it as
		// the retransmit request it is.
		if (msg.nextCommitmentNumber === 0n) {
			const v2Txid = this._inFlightUnsignedV2Txid();
			if (
				!v2Txid ||
				!msg.nextFundingTxid ||
				!msg.nextFundingTxid.equals(v2Txid)
			) {
				return this._failChannelWithWireError(
					'channel_reestablish next_commitment_number is 0'
				);
			}
		}

		// ── Data loss protection: validate yourLastPerCommitmentSecret ──
		if (msg.nextRevocationNumber > 0n) {
			const expectedSecret = getPerCommitmentSecret(
				this._state.localPerCommitmentSeed,
				msg.nextRevocationNumber - 1n
			);
			if (
				!msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32)) &&
				!msg.yourLastPerCommitmentSecret.equals(expectedSecret)
			) {
				// BOLT 2: MUST fail the channel — the peer is lying about (or has
				// corrupted) our revocation chain. Wire error like the DLP path.
				return this._failChannelWithWireError(
					'Invalid per-commitment secret in channel_reestablish'
				);
			}
		}

		// ── Data loss protection: WE fell behind (BOLT 2) ──
		// The peer expects a commitment/revocation beyond anything our restored
		// state ever produced AND its yourLastPerCommitmentSecret passed the
		// validation above while being non-zero: that secret is only derivable
		// from OUR seed at an index we have not reached, so the peer provably
		// holds a newer channel state than we do (we lost data). We MUST NOT
		// broadcast our commitment - it is revoked in the peer's view and would
		// be swept by the justice path. Send an error so the honest peer force
		// closes with ITS commitment, then sweep our to_remote from that.
		// The proof is only sound when the secret's index (nextRevocationNumber
		// minus 1) is one our restored state has NOT revoked yet (released
		// indices run 0..localCommitmentNumber-1): a malicious peer always
		// holds our already-released secrets, and an old secret must not let it
		// freeze the channel with a fake gap.
		if (
			(msg.nextCommitmentNumber > this._state.remoteCommitmentNumber + 1n ||
				msg.nextRevocationNumber > this._state.localCommitmentNumber + 1n) &&
			msg.nextRevocationNumber > this._state.localCommitmentNumber &&
			!msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32))
		) {
			this._state.dataLossDetected = true;
			this._state.dlpRemotePerCommitmentPoint = msg.myCurrentPerCommitmentPoint;
			this._state.recoveryCloseReason = 'local-data-loss';
			this._state.state = ChannelState.ERRORED;
			return [
				// Persist FIRST: a crash between the error send and the peer's
				// force-close must not forget that broadcasting is forbidden.
				{ type: ChannelActionType.PERSIST_STATE },
				declMsg(
					MessageType.ERROR,
					encodeErrorMessage({
						channelId: this._state.channelId!,
						data: Buffer.from(
							'peer proved our channel state is stale (data loss); awaiting your force close',
							'ascii'
						)
					})
				),
				{
					type: ChannelActionType.ERROR,
					message:
						'Channel fell behind: peer proved our state is stale (data loss); refusing to broadcast, awaiting peer force close'
				}
			];
		}

		// ── StateUncertain (recovery 5.6): unprovable restored state ──
		// A compatible reestablish is NOT proof of currency. BOLT 2's
		// stale-state proof only works in one direction: a valid FUTURE
		// secret proves we fell behind (the branch above), but nothing in
		// channel_reestablish attests the peer's HIGHEST state - a malicious
		// peer can under-report counters compatible with our restored state
		// while holding a newer one (it always holds our previously released
		// secrets), wait for us to broadcast, and take everything through the
		// justice path. Exactness must come from recovery-storage provenance
		// (the Phase 6 wire barrier); the restore driver leaves this flag off
		// only when it holds that proof. Without it the sole safe resolution
		// is the DLP path: never resume, never retransmit from an unprovable
		// state, never broadcast; ask the peer to close with ITS commitment
		// and sweep our to_remote from that.
		if (this._state.stateUncertain) {
			this._state.recoveryCloseReason = 'state-uncertain';
			this._state.state = ChannelState.ERRORED;
			return [
				// Persist FIRST: a crash between the error send and the peer's
				// force-close must not forget that broadcasting is forbidden.
				{ type: ChannelActionType.PERSIST_STATE },
				declMsg(
					MessageType.ERROR,
					encodeErrorMessage({
						channelId: this._state.channelId!,
						data: Buffer.from(
							'restored channel state cannot be proven current (recovery); awaiting your force close',
							'ascii'
						)
					})
				),
				{
					type: ChannelActionType.ERROR,
					message:
						'Restored state is unprovable (StateUncertain): refusing to resume or broadcast, awaiting peer force close'
				}
			];
		}

		// ── Commitment retransmission logic ──
		// msg.nextCommitmentNumber is the next commitment the peer expects to RECEIVE from us.
		// We've created up to remoteCommitmentNumber commitments for them.
		if (msg.nextCommitmentNumber > this._state.remoteCommitmentNumber + 1n) {
			// Peer expects a commitment we've never created — irrecoverable gap
			return this._heldReestablishGapFailure(
				'Remote expects future commitment we have not created'
			);
		}

		// ── Revocation retransmission logic ──
		// msg.nextRevocationNumber is the next revocation the peer expects from us.
		// We can only have revoked up to localCommitmentNumber commitments.
		// A value of EXACTLY localCommitmentNumber + 1 is the sig-in-flight
		// case, not a gap: the peer signed a commitment we never received (the
		// connection died between its updates/signature and us). Its own
		// retransmission (updates + commitment_signed, triggered by our
		// next_commitment_number) brings us level, after which we revoke
		// normally. Only a larger gap is irrecoverable.
		if (msg.nextRevocationNumber > this._state.localCommitmentNumber + 1n) {
			// Peer expects a revocation we've never created — irrecoverable
			return this._heldReestablishGapFailure(
				'Remote expects future revocation we have not sent'
			);
		}

		// Collected separately from `actions`: when the peer missed BOTH our
		// last revoke_and_ack AND our last commitment_signed, BOLT 2 requires
		// retransmission in the ORIGINAL relative order (lastSentWasRevoke). A
		// fixed revoke-first replay of a crossed round (we signed first, then
		// revoked for the peer's crossed commitment) desyncs a conformant peer
		// and force-closes.
		const revokeRetransmit: ChannelAction[] = [];
		if (msg.nextRevocationNumber + 1n === this._state.localCommitmentNumber) {
			// Peer missed our last revoke_and_ack — retransmit
			if (
				this._state.lastSentRevokeSecret &&
				this._state.lastSentRevokeNextPoint
			) {
				const revokeMsg: IRevokeAndAckMessage = {
					channelId: this._state.channelId!,
					perCommitmentSecret: this._state.lastSentRevokeSecret,
					nextPerCommitmentPoint: this._state.lastSentRevokeNextPoint
				};
				// option_taproot: the original revoke_and_ack advertised our
				// next-commitment verification nonce, and handleRevokeAndAck
				// requires it unconditionally, so a rebuild without it is
				// rejected by the very peer that asked for the retransmission
				// and the interrupted round never resumes (issue 293). The
				// nonce is deterministic per commitment height and the height
				// has not moved since the original send, so this re-advertises
				// byte-identically what the original carried.
				if (isTaprootChannel(this._state.channelType)) {
					revokeMsg.nextLocalNonce = this._ensureLocalNextNonce();
				}
				revokeRetransmit.push(
					replayMsg(
						MessageType.REVOKE_AND_ACK,
						encodeRevokeAndAckMessage(revokeMsg)
					)
				);
			}
		}
		// revoke_and_ack sent BEFORE the commitment_signed originally (or no
		// commitment_signed recorded after it): keep the revoke first. Only when
		// the revoke was the LAST thing we sent does it replay after the
		// commitment_signed below.
		if (this._state.lastSentWasRevoke !== true) {
			actions.push(...revokeRetransmit);
			revokeRetransmit.length = 0;
		}

		// An in-flight splice means commitment retransmission must follow the
		// SPLICE rules (the mid-splice commitment_signed reuses the same commitment
		// number) — the generic path below would replay a stale pre-splice
		// commitment_signed and desync the channel. EXCEPTION: once the splice is
		// fully signed and awaiting its lock (isSplicePendingLock), normal update
		// traffic has resumed and commitments flow as start_batch batches, which
		// DO need the generic un-acked-update replay + a batch-aware retransmit.
		const spliceActive = !!(this._spliceSession || this._state.spliceInFlight);
		// isSplicePendingLock() requires state === SPLICING, but at this point
		// in the handshake the channel still sits in AWAITING_REESTABLISH (the
		// restore-state block runs further down) — look through it via
		// preReestablishState, or the pending-lock replays below can never fire
		// on reconnect and a round interrupted by the disconnect never resumes.
		const effectiveState =
			this._state.state === ChannelState.AWAITING_REESTABLISH
				? this._state.preReestablishState
				: this._state.state;
		const pendingLock =
			effectiveState === ChannelState.SPLICING &&
			this._state.spliceInFlight?.sentTxSignatures === true &&
			this._state.spliceInFlight?.receivedTxSignatures === true;

		// ── Retransmit un-acked update messages (BOLT 2) ──
		// Every queued update the peer has not acknowledged with a
		// revoke_and_ack may have been lost with the connection (the peer
		// forgets uncommitted updates; a restarted peer restores a state that
		// may predate them). Replay them verbatim BEFORE any retransmitted
		// commitment_signed so the signature always follows the updates it
		// covers. Peers that did keep them treat the replays idempotently
		// (duplicate add ids ignored; fulfill/fail of an already
		// fulfilled/failed HTLC is a no-op).
		if (!spliceActive || pendingLock) {
			for (const update of this._state.pendingLocalUpdates) {
				actions.push(replayMsg(update.type as MessageType, update.payload));
			}
		}

		// ── Retransmit our pending-lock commitment BATCH if the peer missed it ──
		// The generic single-message path below can't: it holds neither the
		// start_batch framing nor the splice-side commitment. Replay the cached
		// wire bytes verbatim (idempotent — same signatures, no nonce reuse).
		if (
			pendingLock &&
			msg.nextCommitmentNumber <= this._state.remoteCommitmentNumber &&
			this._state.remoteCommitmentNumber > 0n
		) {
			if (this._lastSentBatch) {
				actions.push(
					replayMsg(MessageType.START_BATCH, this._lastSentBatch.startBatch)
				);
				for (const c of this._lastSentBatch.commitments) {
					actions.push(replayMsg(MessageType.COMMITMENT_SIGNED, c));
				}
			} else if (
				this._signer &&
				this._state.channelId &&
				this._state.spliceInFlight &&
				this._state.lastSentCommitmentSigned &&
				!isTaprootChannel(this._state.channelType)
			) {
				// Restart mid-round: the cached wire bytes died with the process.
				// Rebuild the batch from persisted material. The current-funding
				// half replays the persisted signature bytes; the splice-side
				// half is RE-SIGNED, which is exact for ECDSA (RFC 6979 is
				// deterministic) over the spliced view at the same commitment
				// number — and the same per-commitment point, because no
				// revoke_and_ack arrived to rotate it.
				const spliced = this._splicedState();
				const point =
					this._state.remoteNextPerCommitmentPoint ??
					this._state.remoteCurrentPerCommitmentPoint;
				if (spliced && point) {
					try {
						const spliceSigned = signRemoteCommitment(
							spliced,
							this._signer,
							point,
							this._state.remoteCommitmentNumber
						);
						const startBatchBytes = encodeStartBatchMessage({
							channelId: this._state.channelId,
							batchSize: 2,
							messageType: MessageType.COMMITMENT_SIGNED
						});
						const currentBytes = encodeCommitmentSignedMessage({
							channelId: this._state.channelId,
							signature: this._state.lastSentCommitmentSigned,
							htlcSignatures: this._state.lastSentHtlcSignatures ?? []
						});
						const spliceBytes = encodeCommitmentSignedMessage({
							channelId: this._state.channelId,
							signature: spliceSigned.signature,
							htlcSignatures: spliceSigned.htlcSignatures,
							fundingTxid: Buffer.from(this._state.spliceInFlight.spliceTxid)
						});
						actions.push(sendMsg(MessageType.START_BATCH, startBatchBytes));
						actions.push(sendMsg(MessageType.COMMITMENT_SIGNED, currentBytes));
						actions.push(sendMsg(MessageType.COMMITMENT_SIGNED, spliceBytes));
						// Cache for any further replay on this connection.
						this._lastSentBatch = {
							startBatch: startBatchBytes,
							commitments: [currentBytes, spliceBytes]
						};
					} catch {
						// Unrebuildable: leave retransmission to the peer's
						// next_funding retransmit flags, as before this change.
					}
				}
			}
		}

		// ── Check if peer missed our commitment_signed ──
		// If peer's nextCommitmentNumber <= remoteCommitmentNumber, they haven't received our latest.
		if (
			!spliceActive &&
			msg.nextCommitmentNumber <= this._state.remoteCommitmentNumber &&
			this._state.remoteCommitmentNumber > 0n
		) {
			// Peer missed our commitment_signed — retransmit.
			// option_taproot: the signing material lives in the cached 98-byte
			// partial_signature_with_nonce, not the all-zero `signature` field, so
			// replay must carry the TLV verbatim or the peer sees an unsigned
			// (zero-sig) commitment. Replaying the same bytes is BOLT-compliant and
			// does not reuse the nonce for a new signature.
			const taprootReest = isTaprootChannel(this._state.channelType);
			if (
				taprootReest
					? this._state.lastSentPartialSignatureWithNonce
					: this._state.lastSentCommitmentSigned
			) {
				const commitMsg: ICommitmentSignedMessage = {
					channelId: this._state.channelId!,
					signature: taprootReest
						? Buffer.alloc(64)
						: this._state.lastSentCommitmentSigned!,
					htlcSignatures: this._state.lastSentHtlcSignatures,
					partialSignatureWithNonce: taprootReest
						? this._state.lastSentPartialSignatureWithNonce!
						: undefined
				};
				actions.push(
					replayMsg(
						MessageType.COMMITMENT_SIGNED,
						encodeCommitmentSignedMessage(commitMsg)
					)
				);
			}
		}

		// Deferred revoke_and_ack (original order: commitment_signed first).
		actions.push(...revokeRetransmit);

		// option_taproot: adopt the peer's freshly-regenerated verification nonce so
		// the next commitment round can co-sign (the peer's old nonce was lost on its
		// reconnect, exactly as ours was).
		if (
			isTaprootChannel(this._state.channelType) &&
			msg.nextLocalNonce &&
			msg.nextLocalNonce.length === 66
		) {
			this._state.remoteNonce = Buffer.from(msg.nextLocalNonce);
		}

		// ── Restore state ──
		if (
			this._state.state === ChannelState.AWAITING_REESTABLISH &&
			this._state.preReestablishState
		) {
			this._state.state = this._state.preReestablishState;
			this._state.preReestablishState = null;
		}

		// ── Interactive-tx resumption ──
		// A channel is never mid-splice and mid-open at once: while a v2 open
		// is in flight, next_funding routes through the v2 handler (the splice
		// handler would answer the open's txid with tx_abort). Everything else
		// takes the splice handler, whose unknown-txid answer also serves a
		// peer resuming a v2 open we dropped or never recorded.
		if (this._v2OpenResuming()) {
			actions.push(...this._handleReestablishV2(msg));
		} else {
			actions.push(...this._handleReestablishSplice(msg));
		}

		// ── Retransmit channel_ready if we sent it previously (BOLT 2 §5) ──
		// Spec trigger: the peer's next_commitment_number == 1 proves it never
		// processed anything past the initial commitment, i.e. it may have
		// missed our channel_ready — retransmit REGARDLESS of our local state
		// (we may already have advanced to NORMAL). The local-state condition
		// is kept as a belt-and-braces fallback for peers that omit the field
		// semantics (pre-ready states always retransmit). Skipped when a
		// channel_ready is already queued: the v2 parked-confirmation flush
		// above runs fundingConfirmed, whose fresh send is byte-identical to
		// this replay, and without the skip one reestablish put both on the
		// wire (issue #421).
		if (
			this._state.localChannelReady &&
			(msg.nextCommitmentNumber === 1n ||
				this._state.state === ChannelState.AWAITING_CHANNEL_READY ||
				this._state.state === ChannelState.AWAITING_FUNDING_CONFIRMED) &&
			!actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					a.messageType === MessageType.CHANNEL_READY
			)
		) {
			const secondPoint = getPerCommitmentPoint(
				this._state.localPerCommitmentSeed,
				1n
			);
			const readyMsg: IChannelReadyMessage = {
				channelId: this._state.channelId!,
				secondPerCommitmentPoint: secondPoint,
				shortChannelId: this._state.scidAlias || undefined
			};
			// option_taproot: re-advertise the SAME commitment-#1 verification nonce
			// (idempotent helper — not a fresh secret) so the pipeline survives a
			// reconnect before the first commitment round.
			if (isTaprootChannel(this._state.channelType)) {
				readyMsg.nextLocalNonce = this._ensureLocalNextNonce();
			}
			actions.push(
				replayMsg(
					MessageType.CHANNEL_READY,
					encodeChannelReadyMessage(readyMsg)
				)
			);
		}

		// ── Flush a v1 funding confirmation parked while disconnected ──
		// The chain watcher's depth callback is one-shot: a confirmation
		// observed while this channel was wrapped in AWAITING_REESTABLISH hit
		// fundingConfirmed's late gate, which stamped fundingConfirmedLate
		// durably and did nothing else. Nothing re-detects it (a restart only
		// races reestablish for the re-armed watch), so consume the stamp here
		// and run the ready flow the observation was owed (issue #420). The v2
		// path has its own flush in _handleReestablishV2. !localChannelReady
		// makes this mutually exclusive with the retransmit block above, so
		// exactly one channel_ready ever leaves; the AWAITING_CHANNEL_READY arm
		// covers the remote-ready-first shape, where the peer's channel_ready
		// landed before (or during) the disconnect but ours never left. The
		// stamp itself stays set: it is durable on-chain evidence for
		// isFundingKnownOnChain, and the state leaving
		// AWAITING_FUNDING_CONFIRMED makes the flush one-shot anyway.
		if (
			!this._state.v2InFlight &&
			this._state.fundingConfirmedLate === true &&
			!this._state.localChannelReady &&
			(this._state.state === ChannelState.AWAITING_FUNDING_CONFIRMED ||
				this._state.state === ChannelState.AWAITING_CHANNEL_READY)
		) {
			actions.push(
				...this.fundingConfirmed(this._state.fundingTxid ?? undefined)
			);
		}

		this._lastReestablishOutcome = actions.some(
			(a) => a.type === ChannelActionType.SEND_MESSAGE && a.replay === true
		)
			? 'replay'
			: 'clean';

		// NOTE (issue #469): a compatible reestablish does NOT lift
		// restoreRecencyUnproven, and deliberately so. Compatibility is not
		// recency. BOLT 2's stale-state proof runs one way only: a valid
		// FUTURE secret proves we fell behind, but nothing in
		// channel_reestablish attests the peer's HIGHEST state, and the peer
		// holding our capsule is the same peer we would be trusting here. One
		// that holds N+1 can under-report N-compatible counters and replay the
		// old secret it already has, wait for an automatic close to publish
		// revoked state N, and take the channel through the justice path. This
		// is the same reasoning the stateUncertain arm above states at length.
		//
		// The hold is therefore permanent, and that IS the protection: the
		// attack needs US to broadcast. A peer that never gets a revoked
		// commitment out of us has to close with a state we can sweep from, or
		// leave the channel open. Resuming is still safe to allow, which is
		// what keeps this narrower than stateUncertain and keeps issue #462's
		// fix working; only the unilateral broadcast we would choose on our
		// own is refused, and the operator's explicit force close remains the
		// labelled exit (5.6).

		// Persist before ANY of the above reaches the peer
		// (docs/RECOVERY-PROTOCOL.md 5.1). Reestablish both mutates state (the
		// restored channel state, the adopted remote nonce, splice resumption)
		// and replays messages built from in-memory state. Without a persist
		// action the whole path bypassed the batch gate, so a transition whose
		// commit had failed could still reach the peer on the next reconnect:
		// exactly the case the gate exists to stop, arriving one connection
		// later. A retransmission is only safe once what justifies it is on
		// disk.
		if (actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)) {
			actions.unshift({ type: ChannelActionType.PERSIST_STATE });
		}

		return actions;
	}

	// ─────────────── Quiescence (STFU) ───────────────

	/**
	 * Get the current quiescence state.
	 */
	getQuiescenceState(): QuiescenceState {
		return this._quiescence.getState();
	}

	/**
	 * Check if the channel is quiescent.
	 */
	isQuiescent(): boolean {
		return this._quiescence.isQuiescent();
	}

	/**
	 * Check if quiescence is in progress (either direction).
	 */
	isQuiescing(): boolean {
		return this._quiescence.isQuiescing();
	}

	/**
	 * Initiate quiescence by sending STFU.
	 * Cannot quiesce with pending HTLCs.
	 */
	initiateQuiescence(): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot quiesce: channel not in NORMAL state'
				}
			];
		}

		// Check for pending HTLCs
		if (this.hasPendingHtlcs()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot quiesce: pending HTLCs exist'
				}
			];
		}

		if (!this._quiescence.initiate()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot quiesce: already quiescing'
				}
			];
		}

		this._state.quiescenceState = QuiescenceState.SENT_STFU;
		this._state.quiescenceInitiator = true;

		const msg: IStfuMessage = {
			channelId: this._state.channelId!,
			initiator: true
		};

		return [sendMsg(MessageType.STFU, encodeStfuMessage(msg))];
	}

	/**
	 * Handle STFU message from peer.
	 */
	/**
	 * Send the stfu reply owed from a latched peer stfu (issue 431) once no
	 * updates are pending. Hooked at the tails of handleCommitmentSigned and
	 * handleRevokeAndAck, the only places the last in-flight update can
	 * settle; self-gates until the drain is genuinely complete.
	 */
	private _maybeAnswerOwedStfu(): ChannelAction[] {
		if (!this._stfuReplyOwed) return [];
		if (this._state.state !== ChannelState.NORMAL) return [];
		if (this.hasPendingHtlcs()) return [];
		this._stfuReplyOwed = false;
		const responseMsg: IStfuMessage = {
			channelId: this._state.channelId!,
			initiator: false
		};
		this._quiescence.completeHandshake();
		this._state.quiescenceState = this._quiescence.getState();
		this._state.quiescenceInitiator = this._quiescence.isInitiator();
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.STFU, encodeStfuMessage(responseMsg))
		];
	}

	handleStfuMessage(msg: IStfuMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected STFU: channel not in NORMAL state'
				}
			];
		}

		// Pending updates split by direction (BOLT 2). The peer's REPLY to our
		// own stfu may not arrive while updates are pending: the replier "MUST
		// NOT send stfu if any of the sender's htlc additions, htlc removals or
		// fee updates are pending for either peer", and on the ordered stream
		// everything that would drain them precedes a conformant reply. An
		// INITIATING stfu, by contrast, legitimately crosses our own in-flight
		// updates, and the receiver "MUST reply with stfu once it can do so":
		// the transition to RECEIVED_STFU happens NOW (so a later peer update
		// is provable divergence, and our own new updates stop), while the
		// reply is owed until the drain completes (issue 431; answered from
		// _maybeAnswerOwedStfu as the last in-flight update settles).
		if (this.hasPendingHtlcs()) {
			if (this._quiescence.getState() !== QuiescenceState.NORMAL) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Cannot accept STFU: pending HTLCs exist'
					}
				];
			}
			const latch = this._quiescence.handlePeerStfu(
				msg.initiator,
				this._state.role === ChannelRole.OPENER
			);
			if (latch.error) {
				return [{ type: ChannelActionType.ERROR, message: latch.error }];
			}
			this._stfuReplyOwed = true;
			this._state.quiescenceState = this._quiescence.getState();
			this._state.quiescenceInitiator = this._quiescence.isInitiator();
			return [{ type: ChannelActionType.PERSIST_STATE }];
		}

		// Concurrent stfu (the peer's message also claims the initiator role
		// while ours is out) is tie-broken in favor of the channel funder
		// (BOLT 2), so both sides agree on who may drive a dependent protocol.
		const result = this._quiescence.handlePeerStfu(
			msg.initiator,
			this._state.role === ChannelRole.OPENER
		);
		if (result.error) {
			return [{ type: ChannelActionType.ERROR, message: result.error }];
		}

		const actions: ChannelAction[] = [];

		if (result.shouldRespond) {
			// We need to respond with our own STFU
			const responseMsg: IStfuMessage = {
				channelId: this._state.channelId!,
				initiator: false
			};
			actions.push(sendMsg(MessageType.STFU, encodeStfuMessage(responseMsg)));

			// Complete the handshake after responding
			this._quiescence.completeHandshake();
		}

		this._state.quiescenceState = this._quiescence.getState();
		this._state.quiescenceInitiator = this._quiescence.isInitiator();

		// If we drove quiescence in order to splice, fire the deferred splice now
		// that we're quiescent. Only the quiescence initiator may send splice_init.
		if (
			this._pendingSplice &&
			this._quiescence.isQuiescent() &&
			this._quiescence.isInitiator()
		) {
			const pending = this._pendingSplice;
			this._pendingSplice = null;
			if (!pending.cancelled) {
				actions.push(
					...this._startSplice(
						pending.relativeSatoshis,
						pending.fundingFeeratePerkw,
						pending.locktime
					)
				);
			} else if (pending.ownsQuiescence) {
				// The operator cancelled the request while our stfu was
				// unanswered (issue #370). Quiescence has no un-stfu and a
				// tx_abort without a splice conversation would only draw a bare
				// echo, so the one spec-clean unwind is to open the conversation
				// we just announced and abort it at once: the peer's session
				// abort exits its quiescence, the echo settles ours. Skipped if
				// the splice_init could not be built (unreachable today); the
				// disconnect fallback still applies there.
				actions.push(
					...this._startSplice(
						pending.relativeSatoshis,
						pending.fundingFeeratePerkw,
						pending.locktime
					)
				);
				if (!actions.some((a) => a.type === ChannelActionType.ERROR)) {
					actions.push(
						...this.initiateSpliceAbort(
							'splice cancelled while awaiting quiescence'
						)
					);
				}
			}
			// A cancelled splice that merely joined a caller-owned handshake is
			// discarded outright: the operator's quiescence completes and
			// stands, exactly as if the splice had never been requested.
		} else if (
			this._pendingSplice &&
			this._quiescence.isQuiescent() &&
			!this._quiescence.isInitiator()
		) {
			// We drove quiescence for a splice but the funder peer initiated
			// concurrently and won the BOLT 2 tie-break: the session is theirs
			// and only the initiator may send splice_init. Drop the request
			// and surface the error so the operator can retry after the
			// peer's session ends (mirrors the failed-quiescence drop in
			// initiateSplice). A cancelled request is dropped silently: the
			// cancel already succeeded, and the peer's session ends the
			// quiescence, so no unwind is owed.
			const lost = this._pendingSplice;
			this._pendingSplice = null;
			// The dead request's wallet configuration dies with it: stale
			// splice-in inputs would otherwise leak into the contributions of
			// a later splice (e.g. a splice-out), and clearing them lets the
			// wallet's pledge TTL free the coins.
			this._resetSpliceDriver();
			if (!lost.cancelled) {
				actions.push({
					type: ChannelActionType.ERROR,
					message:
						'Splice request dropped: concurrent stfu lost the funder tie-break, peer is the quiescence initiator'
				});
			}
		}

		return actions;
	}

	/**
	 * Exit quiescence and resume normal operation.
	 */
	exitQuiescence(): ChannelAction[] {
		if (!this._quiescence.exitQuiescence()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot exit quiescence: not quiescent'
				}
			];
		}
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;
		return [];
	}

	// ─────────────── Splicing ───────────────

	/**
	 * Get the current splice session, if any.
	 */
	getSpliceSession(): SpliceSession | null {
		return this._spliceSession;
	}

	/**
	 * Initiate a splice operation.
	 * Channel must be quiescent (QUIESCENT state) before splicing.
	 * @param relativeSatoshis - positive for splice-in, negative for splice-out
	 * @param fundingFeeratePerkw - feerate for the splice tx
	 * @param locktime - locktime for the splice tx
	 */
	initiateSplice(
		relativeSatoshis: bigint,
		fundingFeeratePerkw: number,
		locktime = 0
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot splice: channel not in NORMAL state'
				}
			];
		}

		// Refused up front, before the stfu leaves (the _startSplice guard is
		// the backstop): a delayed echo of the outstanding abort would be
		// indistinguishable from an abort of the new session.
		if (this._spliceAbortPending) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot splice: a previous splice abort is not yet acknowledged'
				}
			];
		}

		// The splice commitment machinery is ECDSA-only: the mid-splice round
		// signs with signRemoteCommitment, which would produce garbage for a
		// MuSig2 funding and wedge the negotiation against a real peer. Refuse
		// up front with a real answer instead. Taproot splicing (aggregate key
		// for the new funding, nonce lifecycle across the splice, batched
		// partials) is tracked separately.
		if (isTaprootChannel(this._state.channelType)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot splice: taproot (MuSig2) channels do not support splicing yet'
				}
			];
		}

		if (!this._state.channelId) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot splice: no channel ID'
				}
			];
		}

		// A splice-in must not grow the channel past the funding cap (2^24 sat,
		// lifted only when option_wumbo was negotiated). Checked up-front, before
		// we quiesce, like the balance check below.
		if (
			relativeSatoshis > 0n &&
			this._state.fundingSatoshis + relativeSatoshis > this._maxFundingSatoshis
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot splice-in: post-splice capacity ${
						this._state.fundingSatoshis + relativeSatoshis
					} exceeds maximum ${this._maxFundingSatoshis}`
				}
			];
		}

		// BOLT 2 tx_complete (issue #423): the reserve rule arms only when a
		// side ADDS a non-funding output. For a splice-in that is the change
		// output, whose emission is decided by the same arithmetic
		// _computeSpliceContributions later uses; the wallet inputs are set
		// before initiation, so the decision is available up-front, on the
		// current balance. An exact-input or dust-folded selection adds no
		// output and stays legal below the reserve.
		if (relativeSatoshis > 0n && this._spliceInInputs) {
			const remoteFundingPubkey = this._state.remoteBasepoints?.fundingPubkey;
			if (remoteFundingPubkey) {
				let walletTotal = 0n;
				for (const w of this._spliceInInputs.inputs) {
					walletTotal += w.value;
				}
				const feeSats = spliceFeeSats(
					estimateSpliceTxWeight({
						walletInputCount: this._spliceInInputs.inputs.length,
						fundingScriptLen: createFundingScript(
							this._state.localBasepoints.fundingPubkey,
							remoteFundingPubkey
						).p2wshOutput.length,
						changeScriptLen: this._spliceInInputs.changeScript.length
					}),
					fundingFeeratePerkw || 253
				);
				const changeSats = walletTotal - relativeSatoshis - feeSats;
				const postCapacity = this._state.fundingSatoshis + relativeSatoshis;
				const reserveSats = v2ReserveWeKeep(
					postCapacity,
					this._state.localConfig.dustLimitSatoshis,
					this._state.remoteConfig.dustLimitSatoshis
				);
				const postLocalSats =
					this._state.localBalanceMsat / 1000n + relativeSatoshis;
				if (
					changeSats >= this.spliceInteractiveTxDustFloor() &&
					postLocalSats < reserveSats
				) {
					return [
						{
							type: ChannelActionType.ERROR,
							message: `Cannot splice-in: the change output makes this a composition the peer must abort, post-splice balance ${postLocalSats} sats below the channel reserve ${reserveSats} sats at the new capacity; splice in at least enough to clear the reserve`
						}
					];
				}
			}
		}

		// Validate splice-out doesn't exceed our balance (cheap to check up-front,
		// before we quiesce, so we don't STFU only to then fail).
		if (relativeSatoshis < 0n) {
			const withdrawSats = -relativeSatoshis;
			const localBalanceSats = this._state.localBalanceMsat / 1000n;
			if (withdrawSats > localBalanceSats) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Cannot splice-out: insufficient local balance'
					}
				];
			}
			// BOLT 2 tx_complete (issue #423): a splice-out adds a destination
			// output, and a side that adds a non-funding output must end at or
			// above the reserve the NEW capacity prices, or the peer MUST abort
			// the negotiation. Refuse up-front rather than burn a quiescence
			// round on a splice our own tx_complete audit would abort.
			const postCapacity = this._state.fundingSatoshis + relativeSatoshis;
			const reserveSats = v2ReserveWeKeep(
				postCapacity,
				this._state.localConfig.dustLimitSatoshis,
				this._state.remoteConfig.dustLimitSatoshis
			);
			if (localBalanceSats - withdrawSats < reserveSats) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: `Cannot splice-out: post-splice balance ${
							localBalanceSats - withdrawSats
						} sats would be below the channel reserve ${reserveSats} sats at the new capacity`
					}
				];
			}
		}

		// Already quiescent — start the splice immediately. Only the
		// quiescence initiator may send splice_init (BOLT 2): a side that
		// merely answered the peer's stfu (or lost the concurrent-stfu funder
		// tie-break) must not drive a dependent protocol into the peer's
		// session.
		if (this._quiescence.isQuiescent()) {
			if (!this._quiescence.isInitiator()) {
				// The refused request's wallet configuration dies with it
				// (see the tie-break drop in handleStfuMessage).
				this._resetSpliceDriver();
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Cannot splice: peer initiated the quiescence session; retry after it ends'
					}
				];
			}
			return this._startSplice(relativeSatoshis, fundingFeeratePerkw, locktime);
		}

		// Not quiescent yet: remember the request and drive quiescence ourselves
		// so we become the quiescence initiator (the side allowed to send
		// splice_init). The deferred splice fires from handleStfuMessage once we
		// reach QUIESCENT. Ownership decides whether a later cancel owes the
		// handshake an unwind: a handshake already in flight stays splice-owned
		// only if an earlier (possibly since-cancelled) splice request opened
		// it; one the operator opened with initiateQuiescence() is theirs.
		const ownsQuiescence = this._quiescence.isQuiescing()
			? this._pendingSplice?.ownsQuiescence ?? false
			: true;
		this._pendingSplice = {
			relativeSatoshis,
			fundingFeeratePerkw,
			locktime,
			cancelled: false,
			ownsQuiescence
		};

		if (this._quiescence.isQuiescing()) {
			// STFU already in flight; just wait for QUIESCENT.
			return [];
		}

		const stfuActions = this.initiateQuiescence();
		// If quiescence couldn't be started (e.g. pending HTLCs), surface the
		// error and drop the pending splice rather than leaving it dangling.
		// Its wallet configuration dies with it (see the tie-break drop in
		// handleStfuMessage).
		if (stfuActions.some((a) => a.type === ChannelActionType.ERROR)) {
			this._pendingSplice = null;
			this._resetSpliceDriver();
		}
		return stfuActions;
	}

	/**
	 * Create the splice session and emit splice_init. Assumes the channel is
	 * NORMAL and QUIESCENT and the request was already validated.
	 */
	private _startSplice(
		relativeSatoshis: bigint,
		fundingFeeratePerkw: number,
		locktime: number
	): ChannelAction[] {
		const params: ISpliceSessionParams = {
			channelId: this._state.channelId!,
			localFundingPubkey: this._state.localBasepoints.fundingPubkey,
			isInitiator: true,
			localRelativeSatoshis: relativeSatoshis,
			fundingFeeratePerkw,
			locktime
		};

		// A prior splice abort is still awaiting its echo. tx_abort carries no
		// attempt identifier, so a delayed echo would be indistinguishable from
		// an abort of THIS fresh session and would cancel it: refuse until the
		// exchange settles (the echo, or a disconnect, clears the latch).
		if (this._spliceAbortPending) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot splice: a previous splice abort is not yet acknowledged'
				}
			];
		}

		// A fresh negotiation opens a fresh tx_abort conversation: an abort of
		// THIS session deserves its echo even if an earlier one on this
		// connection was already answered.
		this._txAbortSent = false;
		this._spliceSession = new SpliceSession(params);
		const result = this._spliceSession.initiate();

		if (!result.ok) {
			this._spliceSession = null;
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		this._state.preSpliceState = this._state.state;
		this._state.state = ChannelState.SPLICING;

		const spliceMsg = result.message as ISpliceMessage;
		// Persist SPLICING (and the pre-splice state it rolls back to) before
		// the peer sees the request.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.SPLICE, encodeSpliceMessage(spliceMsg))
		];
	}

	/**
	 * Refuse an incoming splice_init with a real protocol answer (issue #371).
	 * A bare ERROR action never reaches the wire, which left the initiator
	 * SPLICING awaiting a splice_ack that never comes and this side silently
	 * QUIESCENT: both HTLC-frozen until a disconnect. Instead, exit the
	 * quiescence the stfu handshake established and answer tx_abort so the
	 * initiator's splice unwind resumes normal operation on both sides. The
	 * local ERROR surface is kept for the operator. Public because the
	 * manager's feature-negotiation refusal (peer never advertised
	 * option_splice) must route through the same unwind: quiescence and the
	 * tx_abort latch are channel state the manager cannot compose itself.
	 * Safe in any channel state: exitQuiescence is a no-op when not
	 * quiescent, and the tx_abort latch matches what just went on the wire.
	 */
	refuseSpliceInit(wireReason: string, errorMessage: string): ChannelAction[] {
		this._quiescence.exitQuiescence();
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;
		const actions: ChannelAction[] = [];
		if (this._state.channelId) {
			actions.push(this._txAbort(this._state.channelId, wireReason));
		}
		actions.push({ type: ChannelActionType.ERROR, message: errorMessage });
		return actions;
	}

	/**
	 * Handle an incoming splice message from remote (acceptor side).
	 * @param msg - The decoded splice message
	 * @param localRelativeSatoshis - Our contribution (positive = splice-in, negative = splice-out)
	 */
	handleSplice(
		msg: ISpliceMessage,
		localRelativeSatoshis = 0n
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice: channel not in NORMAL state'
				}
			];
		}

		if (!this._quiescence.isQuiescent()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot accept splice: channel must be quiescent'
				}
			];
		}

		// Mirror of initiateSplice: the ECDSA-only splice commitment machinery
		// cannot serve a MuSig2 funding. Refuse ON THE WIRE (tx_abort) so the
		// peer stops waiting for splice_ack, and unwind the quiescence the
		// handshake already established so this side resumes normal operation
		// instead of sitting silently quiescent on a splice it rejected.
		if (isTaprootChannel(this._state.channelType)) {
			return this.refuseSpliceInit(
				'taproot splicing unsupported',
				'Cannot accept splice: taproot (MuSig2) channels do not support splicing yet'
			);
		}

		if (!this._state.channelId) {
			// No tx_abort can be composed without a channel ID, but the local
			// quiescence unwind must still run.
			return this.refuseSpliceInit(
				'no channel ID',
				'Cannot accept splice: no channel ID'
			);
		}

		const params: ISpliceSessionParams = {
			channelId: this._state.channelId,
			localFundingPubkey: this._state.localBasepoints.fundingPubkey,
			isInitiator: false,
			localRelativeSatoshis,
			fundingFeeratePerkw: msg.fundingFeeratePerkw,
			locktime: msg.locktime
		};

		// A prior splice abort of ours is still awaiting its echo, so this
		// splice_init crossed our tx_abort on the wire. Adopting a session now
		// would let the delayed echo cancel it (tx_abort carries no attempt
		// identifier), and BOLT 2 forbids answering with another tx_abort while
		// ours is outstanding. Stay silent: the crossing tx_abort aborts the
		// peer's attempt when it lands, and its echo settles the exchange.
		if (this._spliceAbortPending) {
			return [];
		}

		// BOLT 2: only the quiescence initiator may initiate a dependent
		// protocol. A splice_init from the side that merely answered our stfu
		// (or lost the concurrent-stfu funder tie-break) violates the session;
		// refuse on the wire rather than adopt a session the sender was not
		// entitled to open.
		if (this._quiescence.isInitiator()) {
			return this.refuseSpliceInit(
				'splice_init from quiescence non-initiator',
				'Cannot accept splice: peer is not the quiescence initiator'
			);
		}

		// Fresh negotiation, fresh tx_abort conversation (see _startSplice).
		this._txAbortSent = false;
		this._spliceSession = new SpliceSession(params);
		const result = this._spliceSession.handleSplice(msg);

		if (!result.ok) {
			this._spliceSession = null;
			return this.refuseSpliceInit(result.error!, result.error!);
		}

		// The combined contributions must not grow the channel past the funding
		// cap (2^24 sat, lifted only when option_wumbo was negotiated).
		const postSpliceCapacity =
			this._state.fundingSatoshis + this._spliceSession.getNetCapacityChange();
		if (postSpliceCapacity > this._maxFundingSatoshis) {
			this._spliceSession = null;
			return this.refuseSpliceInit(
				'post-splice capacity exceeds maximum',
				`Cannot accept splice: post-splice capacity ${postSpliceCapacity} exceeds maximum ${this._maxFundingSatoshis}`
			);
		}

		this._state.preSpliceState = this._state.state;
		this._state.state = ChannelState.SPLICING;

		const ackMsg = result.message as ISpliceAckMessage;
		// Persist SPLICING (and the pre-splice state it rolls back to) before
		// the peer sees the acceptance.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.SPLICE_ACK, encodeSpliceAckMessage(ackMsg))
		];
	}

	/**
	 * Handle splice_ack from remote (initiator side).
	 */
	handleSpliceAck(msg: ISpliceAckMessage): ChannelAction[] {
		// A splice abort of ours is still awaiting its echo: any splice_ack the
		// peer sent before processing our tx_abort answers a dead splice_init
		// (the cancelled-while-quiescing unwind aborts in the same batch as the
		// splice_init, so the ack always crosses it). BOLT 2 forbids a second
		// tx_abort while ours is outstanding; stay silent. Must precede the
		// state guard: the unwind has already restored NORMAL by the time the
		// crossing ack arrives.
		if (this._spliceAbortPending) {
			return [];
		}
		if (this._state.state !== ChannelState.SPLICING) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice_ack: channel not in SPLICING state'
				}
			];
		}

		if (!this._spliceSession) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice_ack: no splice session'
				}
			];
		}

		const result = this._spliceSession.handleSpliceAck(msg);
		if (!result.ok) {
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		// The peer's splice_ack contribution counts toward capacity too: the
		// combined post-splice capacity must stay under the funding cap (2^24 sat,
		// lifted only when option_wumbo was negotiated). Unwind like the
		// require_confirmed_inputs failure below.
		const postSpliceCapacity =
			this._state.fundingSatoshis + this._spliceSession.getNetCapacityChange();
		if (postSpliceCapacity > this._maxFundingSatoshis) {
			const actions: ChannelAction[] = [
				this._txAbort(
					this._state.channelId!,
					'post-splice capacity exceeds maximum'
				)
			];
			actions.push(
				...this.abortSplice(
					`post-splice capacity ${postSpliceCapacity} exceeds maximum ${this._maxFundingSatoshis}`
				)
			);
			actions.push({
				type: ChannelActionType.ERROR,
				message: `splice aborted: post-splice capacity ${postSpliceCapacity} exceeds maximum ${this._maxFundingSatoshis}`
			});
			return actions;
		}

		// Honor the peer's require_confirmed_inputs: contributing an unconfirmed
		// wallet input would make the peer tx_abort later anyway — fail fast and
		// unwind cleanly before any tx_add_input goes out.
		if (
			this._spliceSession.getRequireConfirmedInputs() &&
			this._spliceInInputs?.inputs.some((i) => i.confirmed === false)
		) {
			const actions: ChannelAction[] = [
				this._txAbort(
					this._state.channelId!,
					'require_confirmed_inputs not satisfied'
				)
			];
			actions.push(
				...this.abortSplice(
					'peer requires confirmed inputs; wallet selection includes unconfirmed UTXOs'
				)
			);
			actions.push({
				type: ChannelActionType.ERROR,
				message:
					'splice aborted: peer requires confirmed inputs but an unconfirmed wallet UTXO was selected'
			});
			return actions;
		}

		// We are the initiator and now in TX_NEGOTIATION. Compute our interactive
		// tx contributions and send the first one; the rest are driven turn-by-turn
		// as the peer responds.
		this._computeSpliceContributions();
		return this._driveSplice();
	}

	/**
	 * Adopt the peer's forwarding policy for the peer-to-us direction, learned
	 * from a channel_update the peer sent us directly (the node verifies the
	 * update signature against the peer's node id BEFORE calling this). Only a
	 * strictly newer timestamp replaces a stored policy. Returns true when the
	 * policy was adopted (caller persists the channel).
	 */
	adoptRemoteForwardingPolicy(policy: IRemoteForwardingPolicy): boolean {
		const existing = this._state.remoteForwardingPolicy;
		if (existing && existing.timestamp >= policy.timestamp) return false;
		this._state.remoteForwardingPolicy = policy;
		return true;
	}

	/**
	 * Record the splice-out destination (where withdrawn funds are paid). Called
	 * by the node before initiating a splice-out.
	 */
	setSpliceOutDestination(script: Buffer, sats: bigint): void {
		this._spliceOutDestination = { script, sats };
	}

	/**
	 * Record the wallet inputs + change script funding a splice-in. Called by the
	 * node (which sourced the UTXOs from its on-chain wallet) before initiating.
	 */
	setSpliceInInputs(inputs: ISpliceWalletInput[], changeScript: Buffer): void {
		this._spliceInInputs = { inputs, changeScript };
	}

	/**
	 * The dust floor an output WE add to a splice transaction must clear.
	 *
	 * Mirrors what InteractiveTxBuilder enforces on every tx_add_output, ours
	 * included: the 546-sat interactive-tx floor, raised to whichever side
	 * negotiated the larger commitment dust limit (the same pair
	 * handleTxAddOutput feeds to setDustLimit on the splice arm). Using
	 * anything lower means emitting an output the peer must reject.
	 */
	spliceInteractiveTxDustFloor(): bigint {
		return bigIntMax(
			bigIntMax(
				this._state.localConfig.dustLimitSatoshis,
				this._state.remoteConfig.dustLimitSatoshis
			),
			DUST_LIMIT_SATS
		);
	}

	/**
	 * The reserve a conforming peer may require us to keep at a given capacity
	 * (v2ReserveWeKeep), derived from the capacity and the two dust limits
	 * alone. The node's splice preflights price post-splice compositions with
	 * it: a splice that parks our balance below this while adding a non-funding
	 * output is one the peer MUST tx_abort (BOLT 2, issue #423).
	 */
	spliceReserveWeKeepSats(capacitySats: bigint): bigint {
		return v2ReserveWeKeep(
			capacitySats,
			this._state.localConfig.dustLimitSatoshis,
			this._state.remoteConfig.dustLimitSatoshis
		);
	}

	/**
	 * Compute the ordered list of interactive-tx contributions we (the initiator)
	 * send for this splice. Currently supports the single-sided cases:
	 *   - splice-out: shared input -> new funding output + destination output
	 *   - splice-in:  shared input -> new funding output (+ caller-provided
	 *                 wallet inputs/change handled by the node, not here)
	 */
	private _computeSpliceContributions(): void {
		this._spliceContributions = [];
		this._spliceContribIndex = 0;
		this._spliceSentTxComplete = false;

		const session = this._spliceSession;
		if (!session || !this._state.fundingTxid) return;
		const localFundingPubkey = this._state.localBasepoints.fundingPubkey;
		const remoteFundingPubkey =
			session.getRemoteFundingPubkey() ||
			this._state.remoteBasepoints?.fundingPubkey;
		if (!remoteFundingPubkey) return;

		// Shared input: the channel's current funding output, signalled via the
		// shared_input_txid TLV with an empty prevTx.
		this._spliceContributions.push({
			kind: 'input',
			sharedInputTxid: this._state.fundingTxid,
			input: {
				serialId: session.nextSerialId()!,
				prevTxid: this._state.fundingTxid,
				prevOutputIndex: this._state.fundingOutputIndex,
				sequence: 0xfffffffd,
				prevTx: Buffer.alloc(0),
				prevTxVout: this._state.fundingOutputIndex
			}
		});

		const oldCapacity = this._state.fundingSatoshis;
		const netChange = session.getNetCapacityChange(); // negative for splice-out
		const feeratePerKw = session.getFundingFeeratePerkw() || 253;
		const newFunding = createFundingScript(
			localFundingPubkey,
			remoteFundingPubkey
		);
		const txWeight = estimateSpliceTxWeight({
			walletInputCount: this._spliceInInputs?.inputs.length ?? 0,
			fundingScriptLen: newFunding.p2wshOutput.length,
			changeScriptLen: this._spliceInInputs?.changeScript.length,
			destinationScriptLen: this._spliceInInputs
				? undefined
				: this._spliceOutDestination?.script.length
		});
		const feeSats = spliceFeeSats(txWeight, feeratePerKw);

		if (this._spliceInInputs) {
			// Splice-in: add the wallet inputs that fund the increase. The new
			// funding output grows by the contribution; the on-chain fee is paid out
			// of the change.
			let walletTotal = 0n;
			for (const w of this._spliceInInputs.inputs) {
				walletTotal += w.value;
				this._spliceContributions.push({
					kind: 'input',
					input: {
						serialId: session.nextSerialId()!,
						prevTxid: extractTxidFromPrevTx(w.prevTx),
						prevOutputIndex: w.prevOutputIndex,
						sequence: w.sequence,
						prevTx: w.prevTx,
						prevTxVout: w.prevOutputIndex
					}
				});
			}

			this._spliceContributions.push({
				kind: 'output',
				output: {
					serialId: session.nextSerialId()!,
					amountSats: oldCapacity + netChange, // netChange = +spliceAmount
					scriptPubkey: newFunding.p2wshOutput
				}
			});

			// A change output below the interactive-tx dust floor cannot be
			// added at all: our own builder rejects it on the way out and the
			// peer rejects it on the way in, aborting an otherwise fundable
			// splice. It becomes extra fee instead. The floor is the NEGOTIATED
			// one, never the 294-sat P2WPKH figure: selection covers exactly
			// amount + fee, so change lands in the 295..545 band routinely
			// rather than exceptionally (issue #389).
			const changeSats = walletTotal - netChange - feeSats;
			if (changeSats >= this.spliceInteractiveTxDustFloor()) {
				this._spliceContributions.push({
					kind: 'output',
					output: {
						serialId: session.nextSerialId()!,
						amountSats: changeSats,
						scriptPubkey: this._spliceInInputs.changeScript
					}
				});
			}
			return;
		}

		// Splice-out: the new funding output is oldCap + funding_contribution (NO
		// separate fee subtraction here). BOLT/CLN compute new_funding =
		// old + relative_satoshis, so the on-chain fee must already be folded into
		// the declared relative_satoshis (node.spliceOut declares -(withdraw+fee)).
		// The withdrawal destination receives the full requested amount, and the
		// fee is implicit (input - outputs). Building the funding output from a
		// DIFFERENT value than the declared relative is what made CLN reject the
		// commitment_signed with a funding_txid mismatch.
		this._spliceContributions.push({
			kind: 'output',
			output: {
				serialId: session.nextSerialId()!,
				amountSats: oldCapacity + netChange,
				scriptPubkey: newFunding.p2wshOutput
			}
		});

		if (this._spliceOutDestination) {
			this._spliceContributions.push({
				kind: 'output',
				output: {
					serialId: session.nextSerialId()!,
					amountSats: this._spliceOutDestination.sats,
					scriptPubkey: this._spliceOutDestination.script
				}
			});
		}
	}

	/**
	 * Send the next interactive-tx contribution (or our tx_complete once they are
	 * exhausted). Invoked when it is our turn: right after splice_ack, and again
	 * each time the peer sends us an interactive-tx message during the splice.
	 */
	private _driveSplice(): ChannelAction[] {
		const session = this._spliceSession;
		if (
			!session ||
			session.getState() !== SpliceState.TX_NEGOTIATION ||
			!this._state.channelId
		) {
			return [];
		}

		// Acceptor side: for a single-sided splice we contribute nothing, so on
		// each of our turns we simply (re)send tx_complete until both sides have
		// completed. The builder resets SENT_COMPLETE -> COLLECTING when the peer
		// adds, so this re-sends correctly across the negotiation.
		if (!session.isInitiator()) {
			const builderState = session.getTxBuilderState();
			if (
				builderState === InteractiveTxState.COLLECTING ||
				builderState === InteractiveTxState.RECEIVED_COMPLETE
			) {
				const err = session.markTxComplete();
				if (err) return [{ type: ChannelActionType.ERROR, message: err }];
				return [
					sendMsg(
						MessageType.TX_COMPLETE,
						encodeTxCompleteMessage({
							channelId: this._state.channelId
						})
					)
				];
			}
			return [];
		}

		if (!this._spliceContributions) {
			return [];
		}

		// Initiator: more contributions to add?
		if (this._spliceContribIndex < this._spliceContributions.length) {
			const c = this._spliceContributions[this._spliceContribIndex++];
			if (c.kind === 'input') {
				const err = session.addInput(c.input);
				if (err) return [{ type: ChannelActionType.ERROR, message: err }];
				const msg: ITxAddInputMessage = {
					channelId: this._state.channelId,
					serialId: c.input.serialId,
					prevTx: c.input.prevTx || Buffer.alloc(0),
					prevTxVout: c.input.prevOutputIndex,
					sequence: c.input.sequence,
					sharedInputTxid: c.sharedInputTxid
				};
				return [
					sendMsg(MessageType.TX_ADD_INPUT, encodeTxAddInputMessage(msg))
				];
			}
			const err = session.addOutput(c.output);
			if (err) return [{ type: ChannelActionType.ERROR, message: err }];
			const outMsg: ITxAddOutputMessage = {
				channelId: this._state.channelId,
				serialId: c.output.serialId,
				amountSats: c.output.amountSats,
				scriptPubkey: c.output.scriptPubkey
			};
			return [
				sendMsg(MessageType.TX_ADD_OUTPUT, encodeTxAddOutputMessage(outMsg))
			];
		}

		// Nothing left to add: send our tx_complete once.
		if (!this._spliceSentTxComplete) {
			this._spliceSentTxComplete = true;
			const err = session.markTxComplete();
			if (err) return [{ type: ChannelActionType.ERROR, message: err }];
			return [
				sendMsg(
					MessageType.TX_COMPLETE,
					encodeTxCompleteMessage({
						channelId: this._state.channelId
					})
				)
			];
		}

		return [];
	}

	/**
	 * Build the splice transaction from the negotiated inputs/outputs and sign the
	 * shared 2-of-2 funding input. Requires the splice session to be in
	 * AWAITING_TX_SIGNATURES and a signer to be set. Returns our signature and the
	 * shared-input/new-funding indices, or null if not ready.
	 *
	 * Both peers run this against the identical negotiated transaction, so they
	 * derive the same txid and can exchange shared-input signatures.
	 */
	buildAndSignSpliceTx(): {
		spliceTxid: Buffer;
		sharedInputIndex: number;
		newFundingOutputIndex: number;
		signature: Buffer;
	} | null {
		const session = this._spliceSession;
		if (!session || session.getState() !== SpliceState.AWAITING_TX_SIGNATURES)
			return null;
		if (
			!this._signer ||
			!this._state.fundingTxid ||
			!this._state.remoteBasepoints
		)
			return null;

		// Idempotent: the splice tx is built once, then referenced by both the
		// commitment round and tx_signatures. Rebuilding would clobber any witness
		// already assembled, so return the cached result if present.
		if (this._spliceTx) {
			return {
				spliceTxid: Buffer.from(this._spliceTx.tx.getHash()),
				sharedInputIndex: this._spliceTx.sharedInputIndex,
				newFundingOutputIndex: this._spliceTx.newFundingOutputIndex,
				signature: this._spliceTx.localSig
			};
		}

		const built = session.buildTransaction();
		if (!built) return null;

		const inputs: ISpliceTxInput[] = built.inputs.map((i) => ({
			serialId: i.serialId,
			prevTxid: i.prevTxid,
			prevOutputIndex: i.prevOutputIndex,
			sequence: i.sequence
		}));
		const outputs: ISpliceTxOutput[] = built.outputs.map((o) => ({
			serialId: o.serialId,
			script: o.scriptPubkey,
			valueSats: o.amountSats
		}));
		const tx = buildSpliceTx(inputs, outputs, built.locktime);

		// The shared input spends our current funding output (a 2-of-2 of the
		// current funding pubkeys).
		const oldFunding = createFundingScript(
			this._state.localBasepoints.fundingPubkey,
			this._state.remoteBasepoints.fundingPubkey
		);
		const sharedInputIndex = findInputIndex(
			tx,
			this._state.fundingTxid,
			this._state.fundingOutputIndex
		);
		if (sharedInputIndex < 0) return null;

		// The new funding (shared) output uses the splice funding pubkeys.
		const remoteSpliceFundingPubkey =
			session.getRemoteFundingPubkey() ||
			this._state.remoteBasepoints.fundingPubkey;
		const newFunding = createFundingScript(
			this._state.localBasepoints.fundingPubkey,
			remoteSpliceFundingPubkey
		);
		const newFundingOutputIndex = findOutputIndex(tx, newFunding.p2wshOutput);

		// SAFETY: never co-sign a negotiated splice tx we have not validated.
		// Our shared-input signature lets the peer spend the current funding
		// output, so a missing/shortchanged new funding output here is how a
		// malicious or buggy peer steals channel funds.
		if (
			this._validateSpliceTxBeforeSigning(tx, newFundingOutputIndex) !== null
		) {
			return null;
		}

		const signature = signSpliceSharedInput(
			tx,
			sharedInputIndex,
			oldFunding.witnessScript,
			this._state.fundingSatoshis,
			this._signer
		);

		// Sign any wallet inputs we contributed (splice-in) and apply their
		// witnesses directly to the tx. Collect them (in tx-input order) so we can
		// send them in tx_signatures. P2TR inputs need the full prevout set
		// (shared funding input included) for the BIP 341 sighash.
		const ourWalletWitnesses: Buffer[][] = [];
		const ourWalletInputIndices: number[] = [];
		if (this._spliceInInputs) {
			const p2wshScript = bitcoin.payments.p2wsh({
				redeem: { output: oldFunding.witnessScript }
			}).output as Buffer;
			const prevouts = this._collectPrevouts(
				tx,
				[...this._spliceInInputs.inputs, ...built.inputs],
				{
					index: sharedInputIndex,
					script: p2wshScript,
					value: this._state.fundingSatoshis
				}
			);
			if (!prevouts) return null;
			for (let i = 0; i < tx.ins.length; i++) {
				if (i === sharedInputIndex) continue;
				const prevTxid = Buffer.from(tx.ins[i].hash);
				const vout = tx.ins[i].index;
				const w = this._spliceInInputs.inputs.find(
					(wi) =>
						extractTxidFromPrevTx(wi.prevTx).equals(prevTxid) &&
						wi.prevOutputIndex === vout
				);
				if (!w) continue;
				const witness = w.signWitness(tx, i, w.value, prevouts);
				tx.setWitness(i, witness);
				ourWalletWitnesses.push(witness);
				ourWalletInputIndices.push(i);
			}
		}

		this._spliceTx = {
			tx,
			sharedInputIndex,
			newFundingOutputIndex,
			oldWitnessScript: oldFunding.witnessScript,
			localSig: signature,
			ourWalletWitnesses,
			ourWalletInputIndices
		};

		return {
			spliceTxid: Buffer.from(tx.getHash()),
			sharedInputIndex,
			newFundingOutputIndex,
			signature
		};
	}

	/**
	 * Pure pre-verification of the peer's shared-input signature, mirroring
	 * exactly what applyPeerSpliceSignature checks before it mutates anything.
	 * Exists so handleTxSignatures can refuse BEFORE _maybeSendSpliceTxSigs
	 * runs (that helper marks our signatures sent as a side effect, and apply
	 * cannot simply move ahead of it: apply advances the splice session out of
	 * AWAITING_TX_SIGNATURES, which is the state the send helper gates on).
	 * Witness data is not part of the BIP 143 sighash, so this verdict is
	 * identical to the re-verification apply performs later.
	 *
	 * Returns null when the signature verifies, else a refusal reason.
	 */
	private _verifySpliceSharedInputSig(remoteSig: Buffer): string | null {
		if (
			!this._spliceSession ||
			!this._spliceTx ||
			!this._state.remoteBasepoints
		) {
			return 'no negotiated splice transaction';
		}
		const { tx, sharedInputIndex, oldWitnessScript } = this._spliceTx;
		const ok = verifySpliceSharedInput(
			tx,
			sharedInputIndex,
			oldWitnessScript,
			this._state.fundingSatoshis,
			this._state.remoteBasepoints.fundingPubkey,
			remoteSig
		);
		return ok ? null : 'invalid peer splice signature';
	}

	/**
	 * Apply the peer's signature on the shared funding input: verify it, assemble
	 * the 2-of-2 witness onto the splice transaction, record the splice outpoint,
	 * and advance the session to AWAITING_SPLICE_LOCKED.
	 *
	 * Must be called after buildAndSignSpliceTx(). Returns the fully-signed splice
	 * transaction, or null on failure.
	 */
	applyPeerSpliceSignature(
		remoteSig: Buffer,
		peerWalletWitnesses: Buffer[][] = []
	): import('bitcoinjs-lib').Transaction | null {
		const session = this._spliceSession;
		if (!session || !this._spliceTx || !this._state.remoteBasepoints)
			return null;

		const {
			tx,
			sharedInputIndex,
			oldWitnessScript,
			localSig,
			newFundingOutputIndex,
			ourWalletInputIndices
		} = this._spliceTx;
		const remoteFundingPubkey = this._state.remoteBasepoints.fundingPubkey;

		const ok = verifySpliceSharedInput(
			tx,
			sharedInputIndex,
			oldWitnessScript,
			this._state.fundingSatoshis,
			remoteFundingPubkey,
			remoteSig
		);
		if (!ok) return null;

		finalizeSpliceSharedWitness(
			tx,
			sharedInputIndex,
			localSig,
			remoteSig,
			this._state.localBasepoints.fundingPubkey,
			remoteFundingPubkey,
			oldWitnessScript
		);

		// Apply the peer's wallet-input witnesses to the non-shared inputs we
		// did not sign ourselves (in ascending input order). Exactly one stack
		// per peer input: surplus or shortfall means the message does not
		// match the negotiated tx.
		const ours = new Set(ourWalletInputIndices);
		const peerIndices: number[] = [];
		for (let i = 0; i < tx.ins.length; i++) {
			if (i === sharedInputIndex || ours.has(i)) continue;
			peerIndices.push(i);
		}
		if (peerWalletWitnesses.length !== peerIndices.length) return null;
		for (let k = 0; k < peerIndices.length; k++) {
			tx.setWitness(peerIndices[k], peerWalletWitnesses[k]);
		}

		const spliceTxid = Buffer.from(tx.getHash());
		const res = session.handleTxSignatures(spliceTxid, newFundingOutputIndex);
		if (!res.ok) return null;

		return tx;
	}

	/**
	 * The fully- or partially-built splice transaction, if any (for broadcast).
	 */
	getSpliceTransaction(): import('bitcoinjs-lib').Transaction | null {
		return this._spliceTx?.tx || null;
	}

	/**
	 * Validate the negotiated splice transaction BEFORE co-signing the shared
	 * funding input. Checks that the new funding output exists, that the fee
	 * implicitly taken from the channel is bounded (vs our own weight estimate
	 * at the negotiated feerate), and that our post-splice balance fits in the
	 * new capacity. Returns an error string, or null if safe to sign.
	 */
	private _validateSpliceTxBeforeSigning(
		tx: import('bitcoinjs-lib').Transaction,
		newFundingOutputIndex: number
	): string | null {
		const session = this._spliceSession;
		if (!session) return 'no splice session';
		if (newFundingOutputIndex < 0 || newFundingOutputIndex >= tx.outs.length) {
			return 'negotiated splice tx has no new funding output';
		}
		const newCapacity = BigInt(tx.outs[newFundingOutputIndex].value);
		const oldCapacity = this._state.fundingSatoshis;
		const netChange = session.getNetCapacityChange();

		// Fee implicitly borne by the channel. Negative means the outputs claim
		// more than the inputs justify — an invalid or dishonest construction.
		const feeFromChannel = oldCapacity + netChange - newCapacity;
		if (feeFromChannel < 0n) {
			return 'splice tx new funding output exceeds the negotiated capacity';
		}

		// Bound the channel-borne fee: generously twice our own estimate for a
		// tx of this shape at the negotiated feerate. A shortchanged funding
		// output shows up here as an absurd implicit fee.
		const feeratePerKw = session.getFundingFeeratePerkw() || 253;
		const maxWeight = estimateSpliceTxWeight({
			walletInputCount: Math.max(0, tx.ins.length - 1),
			changeScriptLen: 22,
			destinationScriptLen: 34
		});
		const maxFeeSats = spliceFeeSats(maxWeight, feeratePerKw) * 2n + 1000n;
		if (feeFromChannel > maxFeeSats) {
			return `splice tx takes an excessive fee from the channel: ${feeFromChannel} sats (max acceptable ${maxFeeSats})`;
		}

		// Our post-splice balance must be non-negative and fit in the new capacity.
		const myFeeMsat = session.isInitiator() ? feeFromChannel * 1000n : 0n;
		const myNewLocalMsat =
			this._state.localBalanceMsat +
			session.getLocalRelativeSatoshis() * 1000n -
			myFeeMsat;
		if (myNewLocalMsat < 0n) {
			return 'splice would make our local balance negative';
		}
		if (newCapacity * 1000n < myNewLocalMsat) {
			return 'splice new funding output cannot cover our local balance';
		}
		return null;
	}

	/**
	 * Handle splice_locked from remote.
	 * When both sides have sent splice_locked, update the channel funding outpoint
	 * and exit quiescence.
	 */
	handleSpliceLocked(msg: ISpliceLockedMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.SPLICING) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice_locked: channel not in SPLICING state'
				}
			];
		}

		if (!this._spliceSession) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice_locked: no splice session'
				}
			];
		}

		const result = this._spliceSession.handleSpliceLocked(msg);
		if (!result.ok) {
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		const actions: ChannelAction[] = [];
		this._syncSpliceInFlight({ remoteSpliceLocked: true });

		// If both sides have sent splice_locked, the splice is complete
		if (this._spliceSession.isComplete()) {
			this.completeSplice();
			actions.push({ type: ChannelActionType.SPLICE_COMPLETE });
		}
		actions.push({ type: ChannelActionType.PERSIST_STATE });

		return actions;
	}

	/**
	 * Send splice_locked after the splice tx is confirmed.
	 */
	sendSpliceLocked(): ChannelAction[] {
		if (this._state.state !== ChannelState.SPLICING) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot send splice_locked: channel not in SPLICING state'
				}
			];
		}

		if (!this._spliceSession) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot send splice_locked: no splice session'
				}
			];
		}

		// Idempotent: the confirmation can be observed more than once (block
		// event + subscription callback + periodic recheck). A duplicate
		// splice_locked on the SAME connection is a protocol violation — CLN
		// fails the channel with "Peer sent duplicate splice_locked message".
		// (Reestablish retransmission after a reconnect goes through
		// _handleReestablishSplice, not here, and stays allowed.)
		if (this._spliceSession.hasSentSpliceLocked()) {
			return [];
		}

		const result = this._spliceSession.sendSpliceLocked();
		if (!result.ok) {
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		const actions: ChannelAction[] = [];
		const lockedMsg = result.message as ISpliceLockedMessage;
		this._syncSpliceInFlight({ localSpliceLocked: true });
		// Persist BEFORE the peer sees splice_locked. Both state changes this
		// step makes (the sent-locked flag above, and completeSplice below,
		// which runs while this array is BUILT, not when it is dispatched) are
		// already applied by the time the action runs, so one leading persist
		// covers the whole step.
		// If both sides have sent splice_locked, the splice is complete.
		const spliceComplete = this._spliceSession.isComplete();
		if (spliceComplete) {
			this.completeSplice();
		}
		actions.push({ type: ChannelActionType.PERSIST_STATE });
		actions.push(
			sendMsg(MessageType.SPLICE_LOCKED, encodeSpliceLockedMessage(lockedMsg))
		);
		if (spliceComplete) {
			actions.push({ type: ChannelActionType.SPLICE_COMPLETE });
		}

		return actions;
	}

	/**
	 * Abort a splice operation.
	 */
	abortSplice(reason?: string): ChannelAction[] {
		if (!this._spliceSession) {
			// A splice may have been requested but is still waiting for quiescence
			// (no session created yet). Nothing left our side beyond the stfu, but
			// stfu cannot be recalled: the request stays parked as cancelled so
			// the deferred hook in handleStfuMessage can unwind the quiescence it
			// completes (splice_init + immediate tx_abort, issue #370). Repeat
			// cancels re-hit this arm and stay a no-op success.
			if (this._pendingSplice) {
				this._pendingSplice.cancelled = true;
				return [];
			}
			// An unsigned in-flight record without a live session (restored from
			// disk before the signature exchange started) is safe to drop.
			const inflight = this._state.spliceInFlight;
			if (
				inflight &&
				!inflight.sentTxSignatures &&
				!inflight.receivedTxSignatures
			) {
				this._state.spliceInFlight = null;
				this._resetSpliceDriver();
				if (this._state.state === ChannelState.SPLICING) {
					this._state.state = this._state.preSpliceState ?? ChannelState.NORMAL;
					this._state.preSpliceState = null;
				}
				return [];
			}
			return [
				{ type: ChannelActionType.ERROR, message: 'No splice session to abort' }
			];
		}

		// Past the point of no return: our tx_signatures have left (or the tx is
		// fully signed), so the splice tx may confirm at any time. Forgetting it
		// now could strand the channel on a spent funding output. (The in-flight
		// record alone is not the threshold — it is created earlier, at the
		// commitment round, for crash-safe persistence.)
		if (
			this._spliceSentTxSigs ||
			this._state.spliceInFlight?.sentTxSignatures ||
			this._state.spliceInFlight?.receivedTxSignatures
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot abort splice: tx_signatures already exchanged, the splice tx may confirm${
						reason ? ` (${reason})` : ''
					}`
				}
			];
		}

		const result = this._spliceSession.abort(reason);
		if (!result.ok) {
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		// Restore pre-splice state
		if (this._state.preSpliceState) {
			this._state.state = this._state.preSpliceState;
			this._state.preSpliceState = null;
		} else {
			this._state.state = ChannelState.NORMAL;
		}

		// Exit quiescence
		this._quiescence.exitQuiescence();
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;

		this._spliceSession = null;
		this._resetSpliceDriver();
		// An unsigned in-flight record (created at the commitment round for
		// crash safety) dies with the aborted splice.
		this._state.spliceInFlight = null;

		return [];
	}

	/**
	 * Operator-initiated splice abort (the ChannelManager.abortSplice path).
	 * Wraps abortSplice() with the durable unwind the peer-driven arms compose
	 * (issue #366): a leading PERSIST_STATE when an in-flight record was
	 * cleared (the record was persisted at the commitment round, so a crash
	 * would otherwise resurrect the aborted splice via restoreSpliceInFlight),
	 * plus a tx_abort so the peer forgets the splice too. The owed tx_abort is
	 * itself durable (state.spliceAbortOwed): re-sent ahead of every
	 * channel_reestablish across disconnects and restarts until the peer's
	 * echo acknowledges it. The send stays out of abortSplice() itself: its
	 * message-handler callers emit their own tx_abort and must not double-send.
	 */
	initiateSpliceAbort(reason?: string): ChannelAction[] {
		const hadRecord = !!this._state.spliceInFlight;
		const hadSession = !!this._spliceSession;
		const wasAwaitingReestablish =
			this._state.state === ChannelState.AWAITING_REESTABLISH;

		const unwind = this.abortSplice(reason);
		// Refusal arms (nothing to abort, or past the point of no return)
		// mutate nothing and keep the record: nothing to persist or send.
		if (unwind.some((a) => a.type === ChannelActionType.ERROR)) {
			return unwind;
		}
		// A pending-splice cancel: quiescence was never reached, so splice_init
		// never left and nothing is on disk. The peer has no splice to forget
		// yet. If our stfu is already out, the request stays parked as
		// cancelled and the deferred hook in handleStfuMessage unwinds the
		// quiescence once the peer's stfu completes it (issue #370).
		if (!hadSession && !hadRecord) {
			return unwind;
		}

		const actions: ChannelAction[] = [];
		if (hadRecord && !this._state.spliceInFlight) {
			// Leads any send so the manager's persist-before-send gate binds
			// the tx_abort's wire bytes into the same persist transaction.
			actions.push({ type: ChannelActionType.PERSIST_STATE });
		}

		// The peer may still hold the splice: we owe it a tx_abort until its
		// echo acknowledges the forget. The disposition is part of the state
		// (captured by the leading persist above) because the in-memory latches
		// do not survive a disconnect or restart, while the reestablish builder
		// re-sends from this flag on every reconnect until the echo settles it.
		this._state.spliceAbortOwed = true;

		if (wasAwaitingReestablish) {
			// Disconnected. The unwind arms route the restored state through
			// _state.state, but while marked for reestablish the live slot is
			// preReestablishState: _state.state must stay AWAITING_REESTABLISH
			// (the manager only initiates reestablish for channels in it), and
			// a stale SPLICING left in preReestablishState would restore a
			// spliceless SPLICING when reestablish completes.
			const target =
				this._state.state !== ChannelState.AWAITING_REESTABLISH
					? this._state.state
					: this._state.preSpliceState ?? ChannelState.NORMAL;
			this._state.preSpliceState = null;
			this._state.preReestablishState =
				target === ChannelState.SPLICING ? ChannelState.NORMAL : target;
			this._state.state = ChannelState.AWAITING_REESTABLISH;
			// No peer to send to: the owed flag makes the reestablish builder
			// emit the tx_abort BEFORE our channel_reestablish, the ordering
			// CLN requires.
		} else if (this._state.channelId) {
			// The peer holds the splice live (splice_init at least crossed, or
			// a commitment-round record exists): tell it to forget. Its echo
			// is swallowed one-shot by the _spliceAbortPending arm of
			// handleTxAbort (which also settles the owed flag); while the latch
			// is set the manager treats a remote error as part of the abort
			// exchange (isSpliceAbortPending). A peer whose tx_signatures
			// already left (unknowable here) will echo but spec-correctly
			// refuse the unwind and retain the splice.
			this._spliceAbortPending = true;
			actions.push(this._txAbort(this._state.channelId, reason));
		}

		return actions;
	}

	/**
	 * Clear the interactive-tx driving state for a splice.
	 */
	private _resetSpliceDriver(): void {
		this._spliceContributions = null;
		this._spliceContribIndex = 0;
		this._spliceSentTxComplete = false;
		this._spliceSentTxSigs = false;
		this._spliceSentCommitment = false;
		this._spliceReceivedCommitment = false;
		this._spliceRemoteCommitmentSig = null;
		this._spliceRemoteHtlcSigs = null;
		this._lastSentBatch = null;
		this._pendingBatch = null;
		this._spliceOutDestination = null;
		this._spliceInInputs = null;
		this._spliceTx = null;
	}

	/**
	 * Create or update the persistent in-flight splice record. Created at the
	 * point of no return (our tx_signatures are about to leave / the splice tx is
	 * fully signed) from the cached splice tx + session, then patched with the
	 * given changes. Survives disconnect and (via serialization) restart.
	 */
	private _syncSpliceInFlight(changes: Partial<ISpliceInFlight>): void {
		if (!this._state.spliceInFlight) {
			const session = this._spliceSession;
			const st = this._spliceTx;
			if (!session || !st) return;
			const remoteFundingPubkey =
				session.getRemoteFundingPubkey() ||
				this._state.remoteBasepoints?.fundingPubkey;
			if (!remoteFundingPubkey || st.newFundingOutputIndex < 0) return;
			// Captured while the builder's prev_txs are still in hand: witness
			// validation after a restart has nothing else to bind and verify
			// the peer's signatures against.
			const prevouts = this._spliceInputPrevouts();
			this._state.spliceInFlight = {
				spliceTxid: Buffer.from(st.tx.getHash()),
				newFundingOutputIndex: st.newFundingOutputIndex,
				newFundingSatoshis: BigInt(st.tx.outs[st.newFundingOutputIndex].value),
				spliceTxHex: st.tx.toHex(),
				fullySigned: false,
				isInitiator: session.isInitiator(),
				localRelativeSatoshis: session.getLocalRelativeSatoshis(),
				remoteRelativeSatoshis: session.getRemoteRelativeSatoshis(),
				remoteFundingPubkey: Buffer.from(remoteFundingPubkey),
				ourSharedInputSig: Buffer.from(st.localSig),
				ourWalletWitnesses: st.ourWalletWitnesses.map((w) =>
					w.map((b) => Buffer.from(b))
				),
				ourWalletInputIndices: [...st.ourWalletInputIndices],
				inputPrevouts: prevouts
					? prevouts.scripts.map((s, i) => ({
							script: Buffer.from(s),
							valueSats: prevouts.values[i]
					  }))
					: [],
				remoteCommitmentSig: this._spliceRemoteCommitmentSig
					? Buffer.from(this._spliceRemoteCommitmentSig)
					: null,
				sentTxSignatures: false,
				receivedTxSignatures: false,
				localSpliceLocked: false,
				remoteSpliceLocked: false,
				confirmed: false
			};
		}
		Object.assign(this._state.spliceInFlight, changes);

		// The splice negotiation is over once tx_signatures have crossed both
		// ways; per the splicing extension quiescence ends with it, and update
		// traffic (HTLCs, fees) resumes while the splice awaits its lock, with
		// every update mirrored onto both fundings via start_batch commitment
		// rounds. Exiting here (not at splice_locked) is what makes
		// pay-during-splice possible; completeSplice's exit remains as the
		// backstop for states persisted before this change.
		// Taproot channels stay parked (quiescent) for the whole splice: the
		// manager's MuSig2 auto-sign path cannot batch both fundings yet, so
		// resuming update traffic would start rounds it cannot finish. Matches
		// canUpdateHtlcsDuringSplice's ECDSA-only restriction.
		if (
			this.isSplicePendingLock() &&
			this._quiescence.isQuiescent() &&
			!isTaprootChannel(this._state.channelType)
		) {
			this._quiescence.exitQuiescence();
			this._state.quiescenceState = QuiescenceState.NORMAL;
			this._state.quiescenceInitiator = false;
		}
	}

	/**
	 * A shallow copy of the channel state re-anchored on the spliced funding
	 * output (new outpoint, capacity and balances), used to build/verify the new
	 * commitment during the mid-splice commitment round WITHOUT mutating the live
	 * state (the old commitment must stay valid until splice_locked).
	 */
	/**
	 * The local balance this channel will settle to when the in-flight splice
	 * locks, or null when no splice is past its point of no return. Uses the
	 * same arithmetic as the spliced commitment (_splicedState), so accounting
	 * surfaces can report the pending balance without reconstructing splice
	 * semantics: the live localBalanceMsat stays pre-splice until splice_locked,
	 * which would make a max splice-in's newly added sats vanish from every
	 * reported figure during the confirmation window.
	 *
	 * Gated on spliceInFlight (recorded at the point of no return): before
	 * that, splice-in wallet UTXOs are still visible in the on-chain balance,
	 * and counting the post-splice figure would double-count them.
	 */
	getPendingSpliceLocalBalanceMsat(): bigint | null {
		if (!this._state.spliceInFlight) return null;
		const spliced = this._splicedState();
		if (spliced) return spliced.localBalanceMsat;
		// The in-memory session is not rebuilt yet (e.g. shortly after a
		// restart): net-change accounting from the persisted record, matching
		// completeSplice's fallback (does not subtract the on-chain fee).
		return (
			this._state.localBalanceMsat +
			this._state.spliceInFlight.localRelativeSatoshis * 1000n
		);
	}

	/**
	 * The reserve WE must keep on the pending splice funding, or null when no
	 * splice is past its point of no return. BOLT 2 prices the reserve at
	 * current capacity and eclair derives it per funding candidate, validating
	 * every update against ALL active commitments, so during the pending-lock
	 * window (updates resume after tx_signatures, before splice_locked) the
	 * pending view binds at the reserve the PENDING capacity prices — on a
	 * peer-funded splice-in the stored value is priced at the smaller old
	 * capacity and admits sends eclair rejects against the new commitment.
	 * Floored at the stored value, never below it: CLN never re-prices across
	 * a splice, so on a splice-out it keeps enforcing the reserve priced at
	 * the ORIGINAL capacity against both views. Same record-first sourcing as
	 * getPendingSpliceLocalBalanceMsat so a restored session (no in-memory
	 * splice state) prices from the persisted point-of-no-return record.
	 */
	private _pendingSpliceKeptReserveSats(): bigint | null {
		if (!this._state.spliceInFlight) return null;
		const pendingCapacity =
			this._splicedState()?.fundingSatoshis ??
			this._state.spliceInFlight.newFundingSatoshis;
		return bigIntMax(
			this._state.remoteConfig.channelReserveSatoshis,
			v2ReserveWeKeep(
				pendingCapacity,
				this._state.localConfig.dustLimitSatoshis,
				this._state.remoteConfig.dustLimitSatoshis
			)
		);
	}

	/**
	 * A conservative ceiling on the outbound HTLC value this channel can add
	 * right now, in msat: local balance minus the reserve the peer requires,
	 * minus (for the opener) the commitment fee with one more HTLC. This is
	 * the arithmetic addHtlc enforces. Conservative in one respect: the fee
	 * counts every active HTLC, while the builder fees only the untrimmed set,
	 * so this can under-report by the trimmed HTLCs' fee share — it never
	 * over-admits.
	 *
	 * Phase-aware on fees: during an update_fee round the next local and
	 * remote commitments can transiently build at different rates (the
	 * builder's own accessors), and the HTLC must be affordable on whichever
	 * is higher — a staged fee increase gates adds immediately, before the
	 * round completes.
	 *
	 * While a splice awaits its lock, every update is mirrored onto BOTH
	 * commitments (current funding + pending splice funding), so the
	 * constraint is the minimum across the live and pending-splice VIEWS,
	 * each priced with its own reserve: a splice-out's candidate commitment
	 * has less to spend, and a splice-in's candidate commitment keeps a
	 * larger reserve (the pending capacity prices it, and eclair validates
	 * every update against all active commitments), so an HTLC the live
	 * commitment could afford would make the spliced one unbuildable or
	 * spec-refusable.
	 */
	getSpendableOutboundMsat(): bigint {
		const spendableFor = (
			localMsat: bigint,
			keptReserveSats: bigint
		): bigint => {
			// Floored at our OWN dust limit, not just the reserve the peer
			// requires. Every conforming pairing already satisfies that (a v1
			// reserve is validated against both dust limits at open, and
			// v2ReserveWeKeep takes the greater of the two), so this changes
			// nothing for them. It binds on a row whose reserve was never
			// derived: sending down to a reserve below our dust limit trims our
			// own to_local out of the commitment WE hold, and if the peer's
			// balance is dust there too that commitment has no outputs at all
			// and cannot be broadcast. The load-time repair fixes the stored
			// value, but it skips a still-negotiating row and only runs on
			// restore, so the invariant is asserted here as well rather than
			// left to depend on which ran first (issues #386, #387).
			const reserveMsat =
				bigIntMax(keptReserveSats, this._state.localConfig.dustLimitSatoshis) *
				1000n;
			let requiredMsat = reserveMsat;
			if (this._state.role === ChannelRole.OPENER) {
				const feeratePerKw = Math.max(
					getLocalCommitmentFeeRate(this._state),
					getRemoteCommitmentFeeRate(this._state)
				);
				// Fee-spike buffer (LND-style, #193): as funder, retain the
				// commitment fee at TWICE the live rate with room for one more
				// HTLC beyond the one being added. An HTLC offered at the exact
				// single-fee ceiling bets the channel on the receiver's margin
				// arithmetic matching ours to the satoshi: the two formulas
				// count active HTLCs from different books, so a sats-scale
				// disagreement turns a boundary offer into a protocol violation
				// the peer may fail the channel over — the sender's unaffordable
				// offer is the BOLT 2 MUST NOT (observed live: a 10,001-sat send
				// at the exact ceiling force-closed an otherwise healthy
				// channel). The buffer also absorbs genuine feerate spikes
				// between now and the commitment that matters.
				//
				// Retained against the funder's FULL cost: the fee at this
				// channel type's base weight plus the two 330-sat anchor
				// outputs the builder deducts separately from it. Without the
				// anchors an exact-ceiling add leaves the funder's commitment
				// output below its negotiated reserve once the builder takes
				// its 660 sats; without the right base weight the ceiling is
				// understated on every taproot channel (#403).
				requiredMsat +=
					funderCommitmentCostSats(
						feeratePerKw * 2,
						this._countActiveHtlcs() + 2,
						this._state.channelType
					) * 1000n;
			}
			const spendable = localMsat - requiredMsat;
			return spendable > 0n ? spendable : 0n;
		};
		const live = spendableFor(
			this._state.localBalanceMsat,
			this._state.remoteConfig.channelReserveSatoshis
		);
		const pendingSplice = this.getPendingSpliceLocalBalanceMsat();
		const pendingReserve = this._pendingSpliceKeptReserveSats();
		if (pendingSplice === null || pendingReserve === null) return live;
		const spliced = spendableFor(pendingSplice, pendingReserve);
		return spliced < live ? spliced : live;
	}

	/**
	 * The channel state re-anchored on the pending splice funding. `base`
	 * defaults to the live state; _localCommitmentEmptyRefusal passes a
	 * live-shaped CANDIDATE instead. A candidate's remoteBalanceMsat override
	 * is intentionally discarded by the remainder derivation below, so a
	 * caller that has both deducted an inbound add from the remote balance
	 * and inserted it into the htlcs map counts it exactly once.
	 */
	private _splicedState(
		base: IChannelState = this._state
	): IChannelState | null {
		if (!this._spliceTx || !this._spliceSession) return null;
		const session = this._spliceSession;
		const tx = this._spliceTx.tx;
		const idx = this._spliceTx.newFundingOutputIndex;
		if (idx < 0 || idx >= tx.outs.length) return null;
		const newCapacity = BigInt(tx.outs[idx].value);

		// On-chain fee taken from the channel (splice-out: the difference the
		// outputs don't account for; splice-in: 0, the fee comes from wallet change).
		// The fee is borne entirely by the splice INITIATOR, so each side computes
		// its own balance and the peer's is the remainder of the new capacity. Both
		// sides therefore agree on the split and build identical commitments.
		const feeFromChannelSats =
			base.fundingSatoshis + session.getNetCapacityChange() - newCapacity;
		const myFeeMsat = session.isInitiator() ? feeFromChannelSats * 1000n : 0n;
		const myNewLocalMsat =
			base.localBalanceMsat +
			session.getLocalRelativeSatoshis() * 1000n -
			myFeeMsat;
		// HTLCs riding through the splice (S-2.M8) hold value in NEITHER
		// balance, so the peer's balance is the remainder of the new capacity
		// AFTER the in-flight HTLC value. Without this each side attributes
		// every HTLC's value to the OTHER side and the two build different
		// commitments ("Invalid splice commitment signature").
		//
		// Summing EVERY entry is correct for in-flight adds and removals too,
		// not just settled committed HTLCs: an HTLC's value leaves a balance at
		// add time and re-enters one only when its entry is DELETED (settlement
		// finalized at removal-commit in handleRevokeAndAck), so
		//   localBalanceMsat + remoteBalanceMsat + Σ(htlcs) = capacity
		// holds continuously, and the commitment builder makes its own
		// per-commitment adjustments for mid-lifecycle entries from the shared
		// htlcs map (buildLocalCommitment / buildRemoteCommitment). The spliced
		// state only needs its base balances to satisfy the same invariant
		// against the NEW capacity, which the remainder computation provides.
		// This is what lets pending-lock commitment rounds (and, with the
		// HTLC gates lifted, pay-during-splice) mirror updates onto both
		// fundings without divergence.
		let htlcInFlightMsat = 0n;
		for (const e of base.htlcs.values()) {
			htlcInFlightMsat += e.amountMsat;
		}
		const theirNewMsat =
			newCapacity * 1000n - myNewLocalMsat - htlcInFlightMsat;

		// The spliced commitment spends the NEW funding 2-of-2, which uses the
		// funding pubkeys negotiated in splice_init/splice_ack — NOT necessarily
		// the original channel funding pubkeys. CLN derives a fresh funding pubkey
		// per splice; beignet reuses its own. Override the funding pubkeys (only)
		// so the commitment's funding witness script and anchor outputs match what
		// the peer signed. All other basepoints (revocation/payment/delayed/htlc)
		// are unchanged by a splice.
		const splicedRemoteBasepoints = base.remoteBasepoints
			? {
					...base.remoteBasepoints,
					fundingPubkey:
						session.getRemoteFundingPubkey() ??
						base.remoteBasepoints.fundingPubkey
			  }
			: base.remoteBasepoints;
		const splicedLocalBasepoints = {
			...base.localBasepoints,
			fundingPubkey: session.getLocalFundingPubkey()
		};

		return {
			...base,
			fundingTxid: Buffer.from(tx.getHash()),
			fundingOutputIndex: idx,
			fundingSatoshis: newCapacity,
			localBalanceMsat: myNewLocalMsat,
			remoteBalanceMsat: theirNewMsat,
			localBasepoints: splicedLocalBasepoints,
			remoteBasepoints: splicedRemoteBasepoints
		};
	}

	/**
	 * BOLT 2 splicing: after the interactive tx completes, both peers send
	 * commitment_signed for the new commitment spending the spliced funding output
	 * (no revoke_and_ack; same commitment number). Builds the splice tx if needed,
	 * signs the peer's new commitment, and sends it once.
	 */
	private _maybeSendSpliceCommitment(): ChannelAction[] {
		const session = this._spliceSession;
		if (
			!session ||
			session.getState() !== SpliceState.AWAITING_TX_SIGNATURES ||
			this._spliceSentCommitment ||
			!this._signer ||
			!this._state.channelId ||
			!this._state.remoteCurrentPerCommitmentPoint
		) {
			return [];
		}
		// Build the splice tx (idempotent) so the new outpoint/capacity are known.
		if (!this._spliceTx && !this.buildAndSignSpliceTx()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Failed to build splice tx for commitment'
				}
			];
		}
		const spliced = this._splicedState();
		if (!spliced) return [];

		const { signature, htlcSignatures } = signRemoteCommitment(
			spliced,
			this._signer,
			this._state.remoteCurrentPerCommitmentPoint,
			this._state.remoteCommitmentNumber
		);
		this._spliceSentCommitment = true;
		// From this point the splice MUST survive a disconnect or restart (the
		// peer holds our commitment_signed and will demand the exchange resume on
		// reestablish — CLN hard-errors otherwise). Record the in-flight splice
		// and persist BEFORE the message leaves.
		this._syncSpliceInFlight({});
		// Splice: the commitment_signed MUST carry the funding_txid of the
		// transaction this commitment spends (the new spliced funding output), so
		// the peer can route it. CLN rejects a splice commitment_signed without it
		// ("Must send funding_txid when sending a commitment batch").
		const spliceTxid = this._spliceTx
			? Buffer.from(this._spliceTx.tx.getHash())
			: undefined;
		const msg: ICommitmentSignedMessage = {
			channelId: this._state.channelId,
			signature,
			htlcSignatures,
			fundingTxid: spliceTxid
		};
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.COMMITMENT_SIGNED, encodeCommitmentSignedMessage(msg))
		];
	}

	/**
	 * Handle the peer's commitment_signed during a splice: ensure we've sent ours,
	 * verify the peer's signature on OUR new commitment, cache it (adopted at
	 * completeSplice), then advance to tx_signatures per the ordering rules.
	 *
	 * The peer sets funding_txid (TLV) to the funding tx its commitment spends.
	 * During a splice both the old funding output and the new spliced output are
	 * valid, so we route the commitment to the matching one. A commitment for the
	 * CURRENT funding output (the peer re-confirming the pre-splice commitment) is
	 * accepted but not adopted as the splice commitment.
	 */
	/**
	 * True while a splice is fully signed (tx_signatures exchanged in BOTH
	 * directions) but not yet locked. In this window the splicing spec resumes
	 * normal channel operation: updates flow again, and every commitment update
	 * is a BATCH signing one commitment per active funding output (the current
	 * one plus the pending splice), announced by start_batch and acknowledged
	 * with a single revoke_and_ack.
	 */
	/**
	 * True when HTLC update traffic may flow during the splice's pending-lock
	 * window. Restricted to ECDSA channels for now: the manager's taproot
	 * (MuSig2) auto-sign path does not batch-sign both fundings yet, so a
	 * taproot channel adding HTLCs mid-splice would commit them on only one
	 * commitment — the exact divergence the batch exists to prevent. Taproot
	 * channels keep the pre-#139 behavior (parked until splice_locked).
	 */
	canUpdateHtlcsDuringSplice(): boolean {
		return (
			this.isSplicePendingLock() && !isTaprootChannel(this._state.channelType)
		);
	}

	/**
	 * Whether this channel can carry HTLC traffic right now: NORMAL, or
	 * mid-splice with update traffic flowing (ECDSA pending-lock). This is the
	 * predicate node-level consumers (router edges, forwarding, invoice hints,
	 * balance) share, so "the router will use it" and "the channel will accept
	 * it" can never disagree. With lookThroughReestablish, a disconnected
	 * channel is judged by the state it will return to — for surfaces like
	 * invoice routing hints that describe the channel rather than use it
	 * immediately.
	 */
	isHtlcUsable(lookThroughReestablish = false): boolean {
		const eff =
			lookThroughReestablish &&
			this._state.state === ChannelState.AWAITING_REESTABLISH
				? this._state.preReestablishState
				: this._state.state;
		if (eff === ChannelState.NORMAL) return true;
		return (
			eff === ChannelState.SPLICING &&
			this._state.spliceInFlight?.sentTxSignatures === true &&
			this._state.spliceInFlight?.receivedTxSignatures === true &&
			!isTaprootChannel(this._state.channelType)
		);
	}

	/**
	 * Whether this channel may take a NEW HTLC: it can carry traffic right now
	 * AND its state is provably current.
	 *
	 * A capsule-restored channel whose recency cannot be proven answers false
	 * (issue #469). Every automatic close is refused while the hold stands, so
	 * its on-chain HTLC deadline backstops can never fire, and an obligation
	 * taken on here has no enforcement behind it: the peer can simply stall.
	 *
	 * A SEPARATE predicate from isHtlcUsable rather than a clause inside it,
	 * because existing HTLCs must still settle and fail off chain. Folding the
	 * hold into isHtlcUsable stopped the deferred-settle drains, and a held
	 * channel with a queued fulfill then never released its preimage - while
	 * the on-chain claim that would otherwise have made up for it is exactly
	 * what the hold disables.
	 *
	 * Answered in ONE place so "the router will offer it" and "the channel will
	 * accept it" cannot disagree: a route the router still publishes is a part
	 * that gets dispatched, and an MPP payment that sends a safe part before a
	 * held part refuses locally leaves the first one locked to its mpp_timeout.
	 */
	acceptsNewHtlcs(lookThroughReestablish = false): boolean {
		if (this._state.restoreRecencyUnproven === true) return false;
		return this.isHtlcUsable(lookThroughReestablish);
	}

	/**
	 * Whether update messages for an EXISTING HTLC may be exchanged right now:
	 * the state test fulfillHtlc, failHtlc and failMalformedHtlc all run,
	 * hoisted so the deferred drains ask the same question the settle itself
	 * will.
	 *
	 * Deliberately wider than isHtlcUsable. SHUTTING_DOWN still settles (BOLT 2
	 * forbids new adds after shutdown, not removals), and the recency hold does
	 * not apply here at all: refusing to release a preimage on a held channel
	 * is how a paid HTLC becomes unclaimable.
	 */
	canSettleHtlcs(): boolean {
		return (
			this._state.state === ChannelState.NORMAL ||
			this._state.state === ChannelState.SHUTTING_DOWN ||
			this.canUpdateHtlcsDuringSplice()
		);
	}

	isSplicePendingLock(): boolean {
		return (
			this._state.state === ChannelState.SPLICING &&
			this._state.spliceInFlight?.sentTxSignatures === true &&
			this._state.spliceInFlight?.receivedTxSignatures === true
		);
	}

	/**
	 * True while a start_batch announced batch is still being collected. The
	 * manager must not auto-reply with our own commitment mid-collection — the
	 * peer's batch is one logical update, and our reply (revoke_and_ack + our
	 * own batch) only goes out once the whole batch has been verified.
	 */
	isCollectingBatch(): boolean {
		return this._pendingBatch !== null;
	}

	/**
	 * Handle start_batch: the peer announces that the next `batchSize`
	 * commitment_signed messages form one logical update.
	 */
	handleStartBatch(msg: IStartBatchMessage): ChannelAction[] {
		// splice_locked can race a commitment round: the peer may have built a
		// batch (old + new funding) before observing our splice_locked, and it
		// arrives after we completed the splice. Per the splicing spec the
		// receiver filters by funding_txid rather than failing — so accept the
		// batch framing post-completion too (the completed splice leaves
		// fundingTxid === spliceFundingTxid) and let the batch handler drop the
		// obsolete old-funding commitment.
		const postSpliceNormal =
			this._state.state === ChannelState.NORMAL &&
			this._state.spliceFundingTxid !== null &&
			this._state.fundingTxid !== null &&
			this._state.spliceFundingTxid.equals(this._state.fundingTxid);
		if (!this.isSplicePendingLock() && !postSpliceNormal) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected start_batch: no fully-signed pending splice'
				}
			];
		}
		if (msg.messageType !== undefined && msg.messageType !== 132) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Unsupported start_batch message_type ${msg.messageType}`
				}
			];
		}
		// Exactly one current funding + one pending splice (no splice RBF yet):
		// the batch MUST carry one commitment_signed per active funding. A
		// smaller batch would revoke on only one funding (see the fund-safety
		// note in _handleCommitmentSignedBatch).
		if (msg.batchSize !== 2) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Unsupported start_batch size ${msg.batchSize} (expected 2)`
				}
			];
		}
		this._pendingBatch = { size: msg.batchSize, msgs: [] };
		return [];
	}

	/**
	 * Handle a commitment batch while a fully-signed splice awaits its lock:
	 * one commitment_signed per active funding output, routed by the
	 * funding_txid TLV. Verification order is fund-safety-critical — the
	 * SPLICE-funding commitment is verified FIRST (a pure check), and only
	 * then is the current-funding commitment run through the standard
	 * handleCommitmentSigned path, which reveals a revocation secret in its
	 * revoke_and_ack. Nothing is revoked unless every commitment in the batch
	 * verifies.
	 */
	private _handleCommitmentSignedBatch(
		msgs: ICommitmentSignedMessage[]
	): ChannelAction[] {
		const inflight = this._state.spliceInFlight;
		if (!inflight) {
			// The batch raced our splice_locked: the peer built it before
			// observing the lock. The commitment for the funding that is now
			// current goes through the standard single-commitment path; the
			// obsolete old-funding commitment is ignored (splicing spec).
			const current = msgs.find(
				(m) =>
					m.fundingTxid &&
					this._state.fundingTxid &&
					m.fundingTxid.equals(this._state.fundingTxid)
			);
			if (!current) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Commitment batch without a pending splice or a current-funding commitment'
					}
				];
			}
			return this.handleCommitmentSigned(current);
		}

		let currentMsg: ICommitmentSignedMessage | null = null;
		let spliceMsg: ICommitmentSignedMessage | null = null;
		for (const m of msgs) {
			if (m.fundingTxid && m.fundingTxid.equals(inflight.spliceTxid)) {
				if (spliceMsg) {
					return [
						{
							type: ChannelActionType.ERROR,
							message: 'Commitment batch has two splice-funding commitments'
						}
					];
				}
				spliceMsg = m;
			} else if (
				!m.fundingTxid ||
				(this._state.fundingTxid &&
					m.fundingTxid.equals(this._state.fundingTxid))
			) {
				if (currentMsg) {
					return [
						{
							type: ChannelActionType.ERROR,
							message: 'Commitment batch has two current-funding commitments'
						}
					];
				}
				currentMsg = m;
			} else {
				const peerTxid = Buffer.from(m.fundingTxid).reverse().toString('hex');
				return [
					{
						type: ChannelActionType.ERROR,
						message: `Commitment batch funding_txid unknown: ${peerTxid}`
					}
				];
			}
		}
		// Fund-safety (both required): the revoke_and_ack the standard path emits
		// reveals a per-commitment secret that revokes commitment N on BOTH active
		// fundings (they share the commitment-number sequence). We must therefore
		// hold a valid, verified peer signature for the NEXT commitment on EACH
		// funding before revoking; a batch missing either commitment would revoke
		// the splice-funding commitment while leaving us with only a stale
		// signature for it, and hence no unilateral exit on the spliced channel.
		if (!currentMsg) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Commitment batch missing the current-funding commitment'
				}
			];
		}
		if (!spliceMsg) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Commitment batch missing the splice-funding commitment'
				}
			];
		}

		// Verify the SPLICE-funding commitment first, at the post-round height
		// (the round advances the local commitment number by one) against the
		// spliced view of the state — a clone re-anchored on the new funding
		// output that inherits any staged feerate, so pending update_fee is
		// applied identically to both commitments. Both the commitment sig and
		// the second-level HTLC sigs are verified BEFORE the standard path
		// reveals any revocation secret.
		if (!this._signer || !this._state.remoteBasepoints) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Commitment batch: no signer or remote basepoints'
				}
			];
		}
		const spliced = this._splicedState();
		if (!spliced) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Commitment batch: cannot rebuild spliced state'
				}
			];
		}
		const nextNum = this._state.localCommitmentNumber + 1n;
		const ourPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			nextNum
		);
		if (
			!verifyRemoteCommitmentSig(
				spliced,
				this._signer,
				ourPoint,
				spliceMsg.signature,
				nextNum
			)
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid batched splice commitment signature'
				}
			];
		}
		// Committed HTLCs may ride through a splice (S-2.M8): the spliced
		// commitment then carries HTLC outputs, and the peer's second-level
		// sigs over them must verify BEFORE the standard path reveals any
		// revocation secret (they are the force-close witness material for the
		// new funding). An HTLC-free splice yields an empty list and this
		// verifies trivially; a count/sig mismatch fails the batch.
		{
			const htlcSigsValid = isTaprootChannel(this._state.channelType)
				? verifyRemoteHtlcSignaturesTaproot(
						spliced,
						ourPoint,
						spliceMsg.htlcSignatures,
						nextNum
				  )
				: verifyRemoteHtlcSignatures(
						spliced,
						this._signer,
						ourPoint,
						spliceMsg.htlcSignatures,
						nextNum
				  );
			if (!htlcSigsValid) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Invalid HTLC signature in a pending-lock batch'
					}
				];
			}
		}
		// The rate the spliced commitment was verified at (before the standard
		// path commits any staged update_fee) — force-close must rebuild at this
		// exact rate to match the adopted signature.
		const spliceSigFeeratePerKw = getLocalCommitmentFeeRate(spliced);

		// Now run the current-funding commitment through the standard path (it
		// verifies at the same post-round height, adopts any staged feerate,
		// advances the commitment number and emits the single revoke_and_ack
		// for the whole batch). The state briefly reads NORMAL so the standard
		// branch accepts it; SPLICING is restored either way.
		let actions: ChannelAction[];
		this._state.state = ChannelState.NORMAL;
		try {
			actions = this.handleCommitmentSigned(currentMsg);
		} finally {
			this._state.state = ChannelState.SPLICING;
		}

		const failed = actions.some((a) => a.type === ChannelActionType.ERROR);
		if (!failed) {
			// Adopt the peer's newest splice-side commitment signature (and the
			// feerate it was made at) so a force-close after the splice confirms
			// uses the latest state at the matching rate.
			this._spliceRemoteCommitmentSig = Buffer.from(spliceMsg.signature);
			this._spliceRemoteHtlcSigs = spliceMsg.htlcSignatures.map((s) =>
				Buffer.from(s)
			);
			this._syncSpliceInFlight({
				remoteCommitmentSig: this._spliceRemoteCommitmentSig,
				remoteCommitmentSigFeeratePerKw: spliceSigFeeratePerKw,
				remoteCommitmentSigLeaseBlockheight: getLocalCommitmentLeaseBlockheight(
					this._state
				),
				remoteHtlcSignatures: this._spliceRemoteHtlcSigs
			});
		}
		return actions;
	}

	private _handleSpliceCommitmentSigned(
		msg: ICommitmentSignedMessage
	): ChannelAction[] {
		const actions: ChannelAction[] = [];
		// Make sure our own commitment_signed has gone out (the peer may send first).
		actions.push(...this._maybeSendSpliceCommitment());

		const spliced = this._splicedState();
		if (!spliced) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected splice commitment_signed: tx not built'
				}
			];
		}

		// Route by funding_txid (internal byte order). If the peer specified a
		// funding_txid that is neither our spliced tx nor the current funding tx,
		// ignore it (BOLT: ignore commitment_signed whose funding_txid is unknown).
		const spliceTxid = this._spliceTx
			? Buffer.from(this._spliceTx.tx.getHash())
			: null;
		if (msg.fundingTxid && spliceTxid && !msg.fundingTxid.equals(spliceTxid)) {
			if (
				this._state.fundingTxid &&
				msg.fundingTxid.equals(this._state.fundingTxid)
			) {
				// Commitment for the CURRENT funding output (still valid during the
				// splice). Accept silently; it is not the spliced commitment.
				return actions;
			}
			// Peer's commitment is for a splice tx we did not build — the two sides
			// constructed different splice transactions. Surface both txids (display
			// order) so the divergence is visible.
			const peerTxid = Buffer.from(msg.fundingTxid).reverse().toString('hex');
			const ourTxid = Buffer.from(spliceTxid).reverse().toString('hex');
			return [
				{
					type: ChannelActionType.ERROR,
					message: `splice commitment_signed funding_txid mismatch: peer=${peerTxid} ours=${ourTxid}`
				}
			];
		}

		// Cannot verify -> must not cache: the signature stored below is the
		// force-close witness material for the new funding, and the received
		// flag it sets gates the rest of the splice round. A plain ERROR, not
		// a wire error: the missing pieces are a LOCAL invariant failure.
		if (!this._signer || !this._state.remoteBasepoints) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot verify splice commitment signature: no signer or remote basepoints'
				}
			];
		}
		const ourPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			this._state.localCommitmentNumber
		);
		const valid = verifyRemoteCommitmentSig(
			spliced,
			this._signer,
			ourPoint,
			msg.signature,
			this._state.localCommitmentNumber
		);
		if (!valid) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid splice commitment signature'
				}
			];
		}
		// Committed HTLCs riding through the splice (S-2.M8) put HTLC
		// outputs on the spliced commitment; verify the peer's second-level
		// sigs over them before caching anything (they are the force-close
		// witness material for the new funding).
		const htlcSigsValid = isTaprootChannel(this._state.channelType)
			? verifyRemoteHtlcSignaturesTaproot(
					spliced,
					ourPoint,
					msg.htlcSignatures,
					this._state.localCommitmentNumber
			  )
			: verifyRemoteHtlcSignatures(
					spliced,
					this._signer,
					ourPoint,
					msg.htlcSignatures,
					this._state.localCommitmentNumber
			  );
		if (!htlcSigsValid) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid splice commitment HTLC signature'
				}
			];
		}
		this._spliceRemoteCommitmentSig = Buffer.from(msg.signature);
		this._spliceRemoteHtlcSigs = msg.htlcSignatures.map((s) => Buffer.from(s));
		this._spliceReceivedCommitment = true;
		// Keep the persisted in-flight record in sync (it may already exist from
		// our own commitment send): the peer's commitment sig must survive a
		// crash, and reestablish derives retransmit_flags from it.
		if (this._state.spliceInFlight) {
			this._syncSpliceInFlight({
				remoteCommitmentSig: this._spliceRemoteCommitmentSig,
				remoteHtlcSignatures: this._spliceRemoteHtlcSigs,
				// The exact parameters this signature covers. Without them a
				// force-close after e.g. an update_fee staged mid-window would
				// rebuild the commitment at the newer rate and attach a
				// signature made for the older one.
				remoteCommitmentSigFeeratePerKw: getLocalCommitmentFeeRate(spliced),
				remoteCommitmentSigLeaseBlockheight:
					getLocalCommitmentLeaseBlockheight(spliced)
			});
		}

		// Commitment round done -> proceed to tx_signatures (acceptor sends first).
		actions.push(...this._maybeSendSpliceTxSigsOrdered());
		return actions;
	}

	/**
	 * tx_signatures ordering (BOLT 2 interactive-tx): the peer with less input
	 * value sends first; on a tie the lower node_id sends first (S-2.M5). The
	 * splice initiator contributes the shared input (100% of prior capacity),
	 * so it USUALLY has more input value and sends last — but an acceptor
	 * splicing in more than the prior capacity contributes more, and
	 * hard-coding acceptor-first there deadlocks against a spec-compliant
	 * peer (both sides wait).
	 */
	private _spliceShouldSignFirst(): boolean {
		const session = this._spliceSession;
		if (!session) return false;
		const builder = session.getTxBuilder();
		// No builder (e.g. a restored post-negotiation session): fall back to
		// the previous acceptor-first convention.
		if (!builder) return !session.isInitiator();
		let ours = 0n;
		let theirs = 0n;
		for (const input of builder.getInputs()) {
			const isOurs = (input.serialId % 2n === 0n) === session.isInitiator();
			const isShared = !input.prevTx || input.prevTx.length === 0;
			// The shared funding input is contributed by the initiator and is
			// worth the pre-splice capacity.
			const value = isShared
				? this._state.fundingSatoshis
				: interactiveInputValueSats(input);
			if (value === null) return !session.isInitiator();
			if (isShared ? session.isInitiator() : isOurs) ours += value;
			else theirs += value;
		}
		if (ours !== theirs) return ours < theirs;
		return this._localNodeIdLower ?? !session.isInitiator();
	}

	private _maybeSendSpliceTxSigsOrdered(): ChannelAction[] {
		const session = this._spliceSession;
		if (!session) return [];
		if (!this._spliceSentCommitment || !this._spliceReceivedCommitment)
			return [];
		if (!this._spliceShouldSignFirst()) return []; // wait for the peer's tx_signatures
		return this._maybeSendSpliceTxSigs();
	}

	/**
	 * Once the interactive tx is complete (AWAITING_TX_SIGNATURES), build and sign
	 * the splice transaction and send our tx_signatures (carrying our shared-input
	 * signature). Idempotent — only sends once.
	 */
	private _maybeSendSpliceTxSigs(): ChannelAction[] {
		const session = this._spliceSession;
		if (
			!session ||
			session.getState() !== SpliceState.AWAITING_TX_SIGNATURES ||
			this._spliceSentTxSigs ||
			!this._signer ||
			!this._state.channelId ||
			// tx_signatures only after the commitment_signed round has completed.
			!this._spliceSentCommitment ||
			!this._spliceReceivedCommitment
		) {
			// No signer / commitment round not done: defer rather than erroring.
			return [];
		}

		const signed = this.buildAndSignSpliceTx();
		if (!signed) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Failed to build/sign splice tx'
				}
			];
		}
		this._spliceSentTxSigs = true;

		// Point of no return: once our tx_signatures leave, the peer can complete
		// and broadcast the splice tx without us. Record (and persist BEFORE
		// sending) everything needed to resume after a disconnect or restart.
		this._state.spliceFundingTxid = signed.spliceTxid;
		this._state.spliceFundingOutputIndex = signed.newFundingOutputIndex;
		this._syncSpliceInFlight({ sentTxSignatures: true });
		// The old outpoint becomes attackable at this same point of no return:
		// once our signature is out the peer can complete and broadcast the
		// splice, and a peer that instead evicts it and publishes a revoked
		// pre-splice commitment spends the OLD output. No WATCH_FUNDING is in
		// this batch (the watch moves when the transaction is actually
		// broadcast), so without recording the leg here a crash between now and
		// the peer's tx_signatures would restore a channel watching only an
		// outpoint that does not exist yet (issue #479).
		const armPreSplice = this._recordPreSpliceSpendWatch(signed.spliceTxid);

		// Our shared-input (2-of-2 funding) signature travels in the
		// shared_input_signature TLV; witnesses carry only the stacks for the
		// wallet inputs we contributed (splice-in), in tx-input order.
		const msg: ITxSignaturesMessage = {
			channelId: this._state.channelId,
			txid: signed.spliceTxid,
			witnesses: this._spliceTx!.ourWalletWitnesses,
			sharedInputSignature: signed.signature
		};
		const actions: ChannelAction[] = [
			// Persist the leg, then arm the watch, then let our signature out.
			// In that order: the record must be on disk before a crash can
			// leave the peer able to broadcast, and the watch must be live
			// before the peer can be told it may.
			{ type: ChannelActionType.PERSIST_STATE },
			...armPreSplice,
			sendMsg(MessageType.TX_SIGNATURES, encodeTxSignaturesMessage(msg))
		];
		// Zero-conf: when the peer's tx_signatures arrived before ours (this
		// send was deferred behind the commitment round), the exchange is
		// complete the moment ours leave — lock immediately (BOLT 2). The
		// mirror ordering (ours first, peer's arrive later) locks in
		// handleTxSignatures.
		if (
			this._isZeroConfChannelType() &&
			this._state.spliceInFlight?.receivedTxSignatures
		) {
			actions.push(...this.sendSpliceLocked());
		}
		return actions;
	}

	/**
	 * Complete the splice: update channel funding outpoint, balances, and exit quiescence.
	 */
	private completeSplice(): void {
		const adopted = this._computeSpliceAdoption();
		if (!adopted) return;
		Object.assign(this._state, adopted);
		this._finishSpliceRuntime();
	}

	/**
	 * The state a splice adoption produces, as a VALUE rather than a mutation.
	 *
	 * Separated out because force close has to know what adopting a CONFIRMED
	 * splice would produce before it decides to adopt anything: it builds the
	 * commitment against the adopted view, and a refusal after the live
	 * channel had already moved leaves a channel that disagrees with the
	 * batch a barrier is still holding against it. One computation, two
	 * callers, so the arithmetic cannot drift between the ordinary
	 * splice_locked path and the last-exit one.
	 *
	 * Null when there is nothing to adopt. Reads runtime and state; writes
	 * neither.
	 */
	private _computeSpliceAdoption(): Partial<IChannelState> | null {
		const inflight = this._state.spliceInFlight;
		if (!this._spliceSession && !inflight) return null;

		const fields: Partial<IChannelState> = {};
		if (!this._spliceSession) {
			// Session-free adoption from the persisted point-of-no-return record:
			// the worst-case restart where the in-memory session could not be
			// rebuilt. The record carries everything the swap needs — beignet
			// reuses its own local funding pubkey across a splice, the peer's is
			// stored, and the balance arithmetic mirrors _splicedState exactly
			// (fee borne by the initiator; in-flight HTLC value in neither
			// balance).
			const newCapacity = inflight!.newFundingSatoshis;
			const feeFromChannelSats =
				this._state.fundingSatoshis +
				inflight!.localRelativeSatoshis +
				inflight!.remoteRelativeSatoshis -
				newCapacity;
			const myFeeMsat = inflight!.isInitiator ? feeFromChannelSats * 1000n : 0n;
			const myNewLocalMsat =
				this._state.localBalanceMsat +
				inflight!.localRelativeSatoshis * 1000n -
				myFeeMsat;
			let htlcInFlightMsat = 0n;
			for (const e of this._state.htlcs.values()) {
				htlcInFlightMsat += e.amountMsat;
			}
			const theirNewMsat =
				newCapacity * 1000n - myNewLocalMsat - htlcInFlightMsat;

			fields.spliceFundingTxid = Buffer.from(inflight!.spliceTxid);
			fields.spliceFundingOutputIndex = inflight!.newFundingOutputIndex;
			fields.fundingTxid = Buffer.from(inflight!.spliceTxid);
			fields.fundingOutputIndex = inflight!.newFundingOutputIndex;
			fields.fundingSatoshis = newCapacity;
			fields.localBalanceMsat = myNewLocalMsat;
			fields.remoteBalanceMsat = theirNewMsat;
			if (this._state.remoteBasepoints) {
				fields.remoteBasepoints = {
					...this._state.remoteBasepoints,
					fundingPubkey: Buffer.from(inflight!.remoteFundingPubkey)
				};
			}
			return this._withSpliceAdoptionTail(fields);
		}

		// Capture the fee-adjusted new outpoint/capacity/balances from the actual
		// splice transaction before the driver is reset.
		const spliced = this._splicedState();
		const txid = this._spliceSession.getSpliceTxid();
		const outputIndex = this._spliceSession.getSpliceFundingOutputIndex();

		if (spliced) {
			fields.spliceFundingTxid = txid;
			fields.spliceFundingOutputIndex = spliced.fundingOutputIndex;
			fields.fundingTxid = spliced.fundingTxid;
			fields.fundingOutputIndex = spliced.fundingOutputIndex;
			fields.fundingSatoshis = spliced.fundingSatoshis;
			fields.localBalanceMsat = spliced.localBalanceMsat;
			fields.remoteBalanceMsat = spliced.remoteBalanceMsat;
			// Adopt the splice-negotiated funding pubkeys: post-splice commitments
			// spend the new funding 2-of-2 and must use these, not the originals.
			fields.localBasepoints = spliced.localBasepoints;
			fields.remoteBasepoints = spliced.remoteBasepoints;
		} else if (txid) {
			// Fallback: net-change accounting (does not subtract the on-chain fee).
			fields.spliceFundingTxid = txid;
			fields.spliceFundingOutputIndex = outputIndex;
			fields.fundingTxid = txid;
			fields.fundingOutputIndex = outputIndex;
			fields.fundingSatoshis =
				this._state.fundingSatoshis +
				this._spliceSession.getNetCapacityChange();
			fields.localBalanceMsat =
				this._state.localBalanceMsat +
				this._spliceSession.getLocalRelativeSatoshis() * 1000n;
			fields.remoteBalanceMsat =
				this._state.remoteBalanceMsat +
				this._spliceSession.getRemoteRelativeSatoshis() * 1000n;
		}

		return this._withSpliceAdoptionTail(fields);
	}

	/**
	 * The funding-independent tail of completeSplice: adopt the peer's
	 * splice-side signatures, reset announcement state for the new funding
	 * generation, exit quiescence, return to NORMAL and clear the splice
	 * bookkeeping. Shared by the session-driven and session-free (post-restart)
	 * adoption paths.
	 */
	private _withSpliceAdoptionTail(
		fields: Partial<IChannelState>
	): Partial<IChannelState> {
		// The reads below have to see the funding swap this same adoption
		// makes, exactly as they did when this ran after the live mutation.
		const adopted = { ...this._state, ...fields } as IChannelState;
		// localConfig.maxHtlcValueInFlightMsat is deliberately NOT re-clamped to
		// the post-splice capacity: it is the limit we NEGOTIATED at open, and
		// the peer holds us to it across splices. Lowering it after a splice-out
		// would make us reject in-flight totals the peer is entitled to once a
		// later splice-in restores capacity. While capacity is low, balance and
		// reserve rules already bound what can actually be in flight, and the
		// gossip htlc_maximum_msat is clamped against current capacity at
		// channel_update build time.
		//
		// Both channelReserveSatoshis, by contrast, ARE revisited (issue #382:
		// BOLT 2 prices the reserve at current capacity), each in ONE direction
		// only, because the two reference peers disagree about what a splice does
		// to the reserve: eclair re-derives BOTH sides from the new capacity the
		// moment fundingTxIndex > 0 (Commitments.scala, v1 channels included),
		// while CLN never re-prices either side across a splice (channeld has no
		// reserve handling at all; an explicit DTODO). Each direction below is
		// the one that is safe against BOTH behaviours; the opposite direction
		// would open a refusal band against one of them, and a reserve refusal is
		// an HTLC the two sides disagree about, which force closes the channel.
		//
		// The reserve we ENFORCE only ever falls. A splice-out leaves us
		// enforcing a reserve the post-splice channel no longer justifies (a
		// channel opened at 5,000,000 and spliced down to 400,000 would refuse
		// every peer HTLC in a 46,000-sat band the peer believes is legal), so
		// lowering to what the new capacity prices closes that band. Raising
		// after a splice-in would open the mirror band against CLN, whose own
		// gate still lets it spend down to the reserve priced at the ORIGINAL
		// capacity; erring low is inert, the peer's own gate binds.
		//
		// reserveWeEnforceAt rather than the v1 helper: the v1 helper prices a v2
		// channel by a rule neither peer applies to it, and its 546-sat policy
		// floor sits above what a SPLICED channel is priced at on either version
		// (eclair takes the derived branch once fundingTxIndex > 0, v1 included).
		// Both mistakes point the same way, at a reserve above what the peer
		// keeps, which is the band this whole adjustment exists to close. Reads
		// `adopted`, so it sees both the capacity and the spliceFundingTxid this
		// same adoption sets.
		const splicedReserve = bigIntMin(
			this._state.localConfig.channelReserveSatoshis,
			reserveWeEnforceAt(adopted, adopted.fundingSatoshis)
		);
		if (splicedReserve !== this._state.localConfig.channelReserveSatoshis) {
			fields.localConfig = {
				...this._state.localConfig,
				channelReserveSatoshis: splicedReserve
			};
			fields.channelReserveVersion = ENFORCED_RESERVE_VERSION;
		}
		// The reserve we KEEP only ever rises. After a splice-in eclair enforces
		// the reserve the NEW capacity prices, so a kept value still priced at
		// the old capacity lets getSpendableOutboundMsat overdraw into an HTLC
		// the peer MUST refuse; raising to v2ReserveWeKeep closes that, and can
		// never overshoot a conforming peer (it is at or above what eclair and
		// CLN each require of us at any dust pairing). Lowering after a
		// splice-out would open the same gap against CLN, which keeps enforcing
		// the value priced at the ORIGINAL capacity; keeping more than a peer
		// demands only costs our own spendable balance. No provenance stamp:
		// channelReserveVersion records the ENFORCED reserve only, and max()
		// against a pure derivation is a fixed point, exactly as in
		// repairKeptChannelReserve. Gated by the same branch rule as
		// reserveWeEnforceAt so the degenerate empty-fields adoption cannot
		// re-price a never-spliced v1 row's wire-negotiated value (every real
		// adoption arm sets fields.spliceFundingTxid before this runs).
		if (adopted.fundingVersion === 2 || adopted.spliceFundingTxid) {
			const keptReserve = bigIntMax(
				this._state.remoteConfig.channelReserveSatoshis,
				v2ReserveWeKeep(
					adopted.fundingSatoshis,
					this._state.localConfig.dustLimitSatoshis,
					this._state.remoteConfig.dustLimitSatoshis
				)
			);
			if (keptReserve !== this._state.remoteConfig.channelReserveSatoshis) {
				fields.remoteConfig = {
					...this._state.remoteConfig,
					channelReserveSatoshis: keptReserve
				};
			}
		}
		// Adopt the peer's signature on our NEW commitment (exchanged during the
		// mid-splice commitment_signed round) so we can unilaterally close the
		// spliced channel. After a restart the in-memory copy is gone but the
		// point-of-no-return record still holds it. If no mid-splice commitment
		// was ever exchanged, fall back to driving a post-splice round.
		const adoptedSig = this.spliceAdoptedRemoteSignature();
		if (adoptedSig) {
			fields.remoteCommitmentSignature = Buffer.from(adoptedSig);
			// Committed HTLCs that rode through the splice (S-2.M8) keep their
			// outputs on the post-splice commitment; adopt the peer's verified
			// second-level sigs over them (empty for an HTLC-free splice).
			fields.remoteHtlcSignatures =
				this._spliceRemoteHtlcSigs ??
				this._state.spliceInFlight?.remoteHtlcSignatures ??
				[];
			// Rebuild at the rate the adopted signature was actually made at, not
			// a feerate that may have been staged (update_fee) but not yet signed.
			fields.lastSignedCommitFeeratePerKw =
				this._state.spliceInFlight?.remoteCommitmentSigFeeratePerKw ??
				getLocalCommitmentFeeRate(adopted);
			fields.lastSignedCommitLeaseBlockheight =
				this._state.spliceInFlight?.remoteCommitmentSigLeaseBlockheight ??
				getLocalCommitmentLeaseBlockheight(adopted);
		} else {
			fields.needsCommitment = true;
		}

		// The pre-splice funding output is spent: its SCID and any exchanged
		// channel_announcement signatures no longer describe this channel.
		// Reset the announcement state so the NEW funding generation is signed
		// and announced fresh (either via announcement depth on the new funding
		// or in response to the peer's re-sent announcement_signatures). The
		// old shortChannelId is kept for forwarding continuity until the new
		// one is computed. Without this reset, the peer's post-splice
		// announcement_signatures get combined with our stale SCID/signatures
		// into an announcement the network rejects ("Bad node_signature_1").
		fields.announcementSigsSent = false;
		fields.announcementSigsReceived = false;
		fields.localAnnouncementNodeSig = null;
		fields.localAnnouncementBitcoinSig = null;
		fields.remoteAnnouncementNodeSig = null;
		fields.remoteAnnouncementBitcoinSig = null;
		fields.fundingConfirmationHeight = 0;
		fields.fundingTxIndex = 0;

		// A batch round can be outstanding at the lock: our commitment_signed
		// pair went out, the peer's revoke_and_ack has not arrived. The generic
		// reestablish retransmit rebuilds from lastSentCommitmentSigned, which
		// still holds the OLD funding's signature; promote the cached
		// splice-side signature (the funding that is current from here on) so a
		// reconnect retransmits a commitment the peer can verify.
		if (this._lastSentBatch && this._lastSentBatch.commitments.length === 2) {
			try {
				const spliceSigned = decodeCommitmentSignedMessage(
					this._lastSentBatch.commitments[1]
				);
				fields.lastSentCommitmentSigned = Buffer.from(spliceSigned.signature);
				fields.lastSentHtlcSignatures = spliceSigned.htlcSignatures.map((h) =>
					Buffer.from(h)
				);
			} catch {
				// Undecodable cache: keep the existing material rather than corrupt it.
			}
		}

		fields.quiescenceState = QuiescenceState.NORMAL;
		fields.quiescenceInitiator = false;
		fields.state = ChannelState.NORMAL;
		fields.preSpliceState = null;
		fields.spliceInFlight = null;
		return fields;
	}

	/**
	 * The peer's signature over our POST-splice commitment, from the cache or
	 * from the persisted point-of-no-return record.
	 *
	 * Its absence is what tells force close that adopting a confirmed splice
	 * would leave the channel holding a signature over the PRE-splice
	 * commitment: non-null, so the "no remote signature" check passes, and
	 * useless, because it signs a funding output the splice has spent.
	 */
	private spliceAdoptedRemoteSignature(): Buffer | null {
		return (
			this._spliceRemoteCommitmentSig ??
			this._state.spliceInFlight?.remoteCommitmentSig ??
			null
		);
	}

	/** Exit quiescence and drop the splice driver: the runtime half. */
	private _finishSpliceRuntime(): void {
		this._quiescence.exitQuiescence();
		this._spliceSession = null;
		this._resetSpliceDriver();
	}

	/**
	 * BOLT 2 quiescence gate: stfu may only be sent (or honored) when no
	 * UPDATES are pending, i.e. nothing is between "sent" and "irrevocably
	 * committed by both sides". A fully-committed live HTLC is NOT a pending
	 * update — rejecting stfu for one (the old behavior) made CLN/eclair
	 * initiated quiescence (and thus splicing) on any busy channel stall until
	 * the peer's quiescence timeout disconnected us (S-2.M8).
	 */
	private hasPendingHtlcs(): boolean {
		if (this.needsCommitment()) {
			return true;
		}
		for (const entry of this._state.htlcs.values()) {
			// An add not yet committed by both sides.
			if (entry.state === HtlcState.PENDING) {
				return true;
			}
			// A removal in flight: fulfilled/failed entries are deleted once the
			// removal is fully committed, so their presence means it is not.
			if (
				entry.state === HtlcState.FULFILLED ||
				entry.state === HtlcState.FAILED
			) {
				return true;
			}
			// Two-phase flags mid-flight (false = the covering commitment round
			// has not completed; absent/true = settled).
			if (
				entry.addRemoteCommitted === false ||
				entry.addLocallyRevoked === false ||
				entry.removalRemoteCommitted === false ||
				entry.removalLocallyRevoked === false ||
				entry.commitCoverPending === true
			) {
				return true;
			}
		}
		return false;
	}

	// ─────────────── Helpers ───────────────

	/**
	 * Maximum total value of dust HTLCs allowed in flight (both directions).
	 * Dust HTLCs are trimmed from the commitment tx, so on a force-close their
	 * entire value is burned to miner fees — this caps that worst case.
	 */
	static readonly MAX_DUST_HTLC_EXPOSURE_MSAT = 5_000_000n; // 5000 sats

	/**
	 * How far past the current block height an incoming HTLC's cltv_expiry may
	 * reach (~5 weeks). Our policy, not a BOLT 2 MUST: the node admits an add
	 * beyond it and fails it back with expiry_too_far once committed.
	 */
	static readonly MAX_HTLC_CLTV_EXPIRY_DELTA = 5040;

	/**
	 * Whether an HTLC of this amount would be trimmed (dust) on at least one of
	 * the two commitments at the given feerate. Mirrors the commitment builder's
	 * trim rule (dust_limit + second-level tx fee): for non-anchor channels the
	 * threshold is feerate-dependent, and every HTLC is a received-HTLC (success
	 * weight, the larger of the two) on one side's commitment, so success weight
	 * is the binding threshold regardless of direction. Anchor channels use
	 * zero-fee second-level txs, making the threshold the static dust limit.
	 */
	private _isDustHtlcAtRate(amountMsat: bigint, feeratePerKw: number): boolean {
		const dustLimitSats =
			this._state.localConfig.dustLimitSatoshis >
			this._state.remoteConfig.dustLimitSatoshis
				? this._state.localConfig.dustLimitSatoshis
				: this._state.remoteConfig.dustLimitSatoshis;
		let secondLevelFeeSats = 0n;
		if (!isAnchorChannel(this._state.channelType)) {
			secondLevelFeeSats = BigInt(
				Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000)
			);
		}
		return amountMsat < (dustLimitSats + secondLevelFeeSats) * 1000n;
	}

	/** Whether an HTLC of this amount would be trimmed (dust) on the commitment. */
	private _isDustHtlc(amountMsat: bigint): boolean {
		return this._isDustHtlcAtRate(
			amountMsat,
			getCommitmentFeeRate(this._state)
		);
	}

	/** Total in-flight dust-HTLC value (both directions) at a feerate, in msat. */
	private _dustExposureAtRateMsat(feeratePerKw: number): bigint {
		let total = 0n;
		for (const entry of this._state.htlcs.values()) {
			if (
				(entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED) &&
				this._isDustHtlcAtRate(entry.amountMsat, feeratePerKw)
			) {
				total += entry.amountMsat;
			}
		}
		return total;
	}

	/** Total in-flight dust-HTLC value (both directions), in msat. */
	private _dustExposureMsat(): bigint {
		return this._dustExposureAtRateMsat(getCommitmentFeeRate(this._state));
	}

	/**
	 * Whether this in-flight received HTLC breached MAX_DUST_HTLC_EXPOSURE_MSAT
	 * when it was ADMITTED (the dustExposureFailback stamp set by
	 * handleUpdateAddHtlc). BOLT 2 ("Bounding exposure to trimmed in-flight
	 * HTLCs"): such an HTLC SHOULD be failed once committed rather than
	 * refused at add time (issue 410). The stamp rather than a live
	 * recomputation: within a synchronously dispatched batch, earlier
	 * final-hop siblings settle (FULFILLED/FAILED) before later entries are
	 * checked and would vanish from a live exposure total, letting the HTLC
	 * that crossed the ceiling slip under it; the stamp is also persisted, so
	 * a restart replay answers identically.
	 */
	receivedHtlcExceedsDustExposure(htlcId: bigint): boolean {
		const entry = this._state.htlcs.get('received-' + htlcId);
		if (!entry) return false;
		if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			return false;
		}
		return entry.dustExposureFailback === true;
	}

	/**
	 * Would the commitment WE hold be built with NO outputs once a peer-driven
	 * update is applied? A refusal reason, or null (issue #386).
	 *
	 * The reserve we enforce on the peer floors at the LOWER of the two dust
	 * limits (v2ReserveWeEnforce, and computeChannelReserve's capacity/5 cap can
	 * land under our own dust limit too), so on an asymmetric-dust channel a
	 * peer balance that clears its reserve can still be dust in OUR commitment.
	 * Pair that with our own balance already under our dust limit, which a v2
	 * open legitimately starts at whenever we contribute little or nothing, and
	 * an ordinary update_add_htlc or update_fee produces a commitment with every
	 * output trimmed. Nothing downstream catches it: the peer builds the same
	 * bytes, so its signature verifies, and prepareForceClose would hand back a
	 * transaction with no outputs, which cannot be broadcast. We would hold no
	 * unilateral exit at all while the peer keeps one. This is the same rule
	 * _v2InitialCommitmentRefusal applies at open, moved to where balances
	 * actually change.
	 *
	 * The cheap gate first: when the reserve we enforce is at or above our own
	 * dust limit, the peer's balance can never fall below it, so their to_remote
	 * output in our commitment always survives and there is nothing to check.
	 * Both handlers admit only when the peer keeps reserve + the commitment fee,
	 * the builder's remote balance is never lower than the live one (it only
	 * takes credits), and with no untrimmed HTLC the builder's fee is at or
	 * below the estimate the handlers use. Every default-configured node sits on
	 * that side of the gate, so the hot path is untouched.
	 *
	 * Past the gate it asks the REAL builder rather than repeating its
	 * arithmetic. buildLocalCommitment also applies the deferred balance credits
	 * of an in-flight settlement round, the second-level fee in the HTLC trim
	 * threshold, the funder's anchor cost and the saturate-at-zero rule; a guard
	 * that re-derived any of those would understate to_local mid-round and
	 * refuse a commitment the builder builds with outputs, which is a force
	 * close of a healthy channel.
	 *
	 * While a fully signed splice awaits its lock, the same question is asked
	 * of the SPLICED view: _splicedState(candidate) re-anchors the candidate
	 * on the new funding, deriving the peer's balance as the remainder of the
	 * new capacity after in-flight HTLC value, so the add's amount counts once
	 * rather than twice. The spliced half runs regardless of the cheap gate:
	 * the reserve we enforce bounds only the peer's LIVE balance, and a peer
	 * splice-out leaves a spliced remainder below it because reserves are not
	 * re-derived until the lock (issue #382). It is skipped when the in-memory
	 * session is not rebuilt (no spliced view exists to check);
	 * _handleCommitmentSignedBatch independently fails closed there before any
	 * revocation. getSpendableOutboundMsat still covers our own sends across
	 * both views (issue #405).
	 */
	private _localCommitmentEmptyRefusal(overrides: {
		remoteBalanceMsat?: bigint;
		pendingFeeratePerKw?: number;
		addedHtlc?: { key: string; entry: IHtlcEntry };
	}): string | null {
		const ourDust = this._state.localConfig.dustLimitSatoshis;
		const liveHalf = this._state.localConfig.channelReserveSatoshis < ourDust;
		const spliceHalf = this.isSplicePendingLock();
		if (!liveHalf && !spliceHalf) return null;
		const candidate: IChannelState = { ...this._state };
		if (overrides.remoteBalanceMsat !== undefined) {
			candidate.remoteBalanceMsat = overrides.remoteBalanceMsat;
		}
		if (overrides.pendingFeeratePerKw !== undefined) {
			candidate.pendingFeeratePerKw = overrides.pendingFeeratePerKw;
		}
		if (overrides.addedHtlc) {
			candidate.htlcs = new Map(this._state.htlcs);
			candidate.htlcs.set(overrides.addedHtlc.key, overrides.addedHtlc.entry);
		}
		const next = this._state.localCommitmentNumber + 1n;
		const point = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			next
		);
		const emptyRefusal = (view: IChannelState, what: string): string | null => {
			let outputCount: number;
			try {
				outputCount = buildLocalCommitment(view, point, next).result.tx.outs
					.length;
			} catch {
				// A commitment we cannot build is strictly worse than one we can,
				// so this refuses rather than admitting on the builder's behalf.
				// It needs remoteBasepoints and fundingTxid, which any channel
				// taking peer updates already has.
				return `Cannot build the ${what} this update would leave us holding`;
			}
			if (outputCount > 0) return null;
			return `Update would trim every output of the ${what} we hold at the ${ourDust}-sat dust limit`;
		};
		if (liveHalf) {
			const refusal = emptyRefusal(candidate, 'commitment');
			if (refusal) return refusal;
		}
		if (spliceHalf) {
			const spliced = this._splicedState(candidate);
			if (spliced) {
				// An update the NEW capacity cannot fund derives a negative
				// balance: the remainder invariant (local + remote + htlcs =
				// capacity) then puts more value in outputs than the spliced
				// funding holds, and the builder happily emits e.g. an
				// untrimmed HTLC output larger than the funding — a
				// consensus-invalid commitment an output-count check alone
				// accepts. With both derived balances non-negative the same
				// invariant bounds every output combination by the capacity,
				// so this is the complete underfunding check.
				if (spliced.localBalanceMsat < 0n || spliced.remoteBalanceMsat < 0n) {
					return `Update would overdraw the ${spliced.fundingSatoshis}-sat pending-splice capacity`;
				}
				return emptyRefusal(spliced, 'pending-splice commitment');
			}
		}
		return null;
	}

	private _countActiveHtlcs(): number {
		let count = 0;
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.state === HtlcState.PENDING ||
				entry.state === HtlcState.COMMITTED
			) {
				count++;
			}
		}
		return count;
	}

	private countPendingHtlcs(direction: HtlcDirection): number {
		let count = 0;
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.direction === direction &&
				(entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED)
			) {
				count++;
			}
		}
		return count;
	}

	private totalInFlightMsat(direction: HtlcDirection): bigint {
		let total = 0n;
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.direction === direction &&
				(entry.state === HtlcState.PENDING ||
					entry.state === HtlcState.COMMITTED)
			) {
				total += entry.amountMsat;
			}
		}
		return total;
	}

	// ─────────────── Channel Announcements (BOLT 7) ───────────────

	/**
	 * Handle announcement depth reached (6 confirmations).
	 * Computes SCID, signs the channel_announcement, and sends announcement_signatures.
	 */
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
		this._state.shortChannelId = scid;
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

	/**
	 * Handle announcement_signatures from remote peer.
	 */
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
			this._state.shortChannelId = msg.shortChannelId;
			this._state.announcementSigsSent = false;
			this._state.localAnnouncementNodeSig = null;
			this._state.localAnnouncementBitcoinSig = null;
		}

		this._state.remoteAnnouncementNodeSig = msg.nodeSignature;
		this._state.remoteAnnouncementBitcoinSig = msg.bitcoinSignature;
		this._state.announcementSigsReceived = true;

		// If we don't have an SCID yet, use theirs
		if (!this._state.shortChannelId) {
			this._state.shortChannelId = msg.shortChannelId;
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
		const hash = crypto
			.createHash('sha256')
			.update(crypto.createHash('sha256').update(data).digest())
			.digest();
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

	/**
	 * Get the SCID if set.
	 */
	getShortChannelId(): Buffer | null {
		return this._state.shortChannelId;
	}

	/**
	 * Get our local SCID alias (sent to peer in channel_ready).
	 */
	getScidAlias(): Buffer | null {
		return this._state.scidAlias;
	}

	/**
	 * Get the remote's SCID alias (received in their channel_ready).
	 */
	getRemoteScidAlias(): Buffer | null {
		return this._state.remoteScidAlias;
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

	// ─────────────── Dual Funding (v2) ───────────────

	/**
	 * Get the dual-funding session (if any).
	 */
	getDualFundingSession(): DualFundingSession | null {
		return this._state.dualFundingSession;
	}

	/**
	 * Initiate opening a v2 (dual-funded) channel. Sends open_channel2.
	 */
	initiateOpenV2(params: IDualFundingParams): ChannelAction[] {
		if (this._state.state !== ChannelState.NONE) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot initiate v2 open: wrong state'
				}
			];
		}

		const v2MaxHtlcErr = validateU64(
			params.maxHtlcValueInFlightMsat,
			'max_htlc_value_in_flight_msat'
		);
		if (v2MaxHtlcErr) {
			return [{ type: ChannelActionType.ERROR, message: v2MaxHtlcErr }];
		}

		// BOLT 2 requires channel_type on open_channel2, so the default is
		// resolved INTO the params before anything else: the wire message
		// must carry it (CLN aborts a type-less open_channel2 outright).
		if (!params.channelType) {
			const defaultType = FeatureFlags.empty();
			defaultType.setCompulsory(Feature.STATIC_REMOTE_KEY);
			params = { ...params, channelType: defaultType.toBuffer() };
		}
		// Admission validation of the type this open would propose, BEFORE
		// any state mutation: taproot v2 signing does not exist, so a
		// taproot (or otherwise unrecognized) type must never leave this
		// method as an OPEN_CHANNEL2. The manager additionally validates
		// against both init vectors; a raw Channel has none, so the
		// presence, structural and taproot rules still hold here.
		const v2TypeErr = validateV2ChannelType(params.channelType);
		if (v2TypeErr) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot initiate v2 open: ${v2TypeErr}`
				}
			];
		}
		// BOLT 2: a scid_alias type must never go out announceable. The
		// trusted path upstream already forces this; enforcing it HERE
		// covers every caller that hands an explicit alias type with the
		// default (announce) channel flags.
		if (hasScidAliasChannelType(params.channelType ?? null)) {
			params = {
				...params,
				channelFlags: (params.channelFlags ?? 0x01) & ~0x01
			};
			this._state.announceChannel = false;
		}

		this._state.fundingVersion = 2;
		this._state.commitmentFeeratePerkw = params.commitmentFeeratePerkw;
		this._state.fundingLocktime = params.locktime;
		// Both sides must build the identical commitment #0: pin our (opener)
		// committed feerate to the NEGOTIATED commitment feerate — the acceptor
		// signs at msg.commitmentFeeratePerkw, and getCommitmentFeeRate reads
		// localConfig for the opener — and record the channel type so
		// anchor/taproot dispatch sees the negotiated value.
		this._state.localConfig.feeratePerKw = params.commitmentFeeratePerkw;
		// The wire message carries first_per_commitment_point as a real EC
		// point; the basepoints struct often holds a zeroed placeholder (the
		// legacy open derives the point at send time too). An all-zero "point"
		// makes CLN reject the whole open_channel2 as unparsable.
		params = {
			...params,
			localBasepoints: {
				...params.localBasepoints,
				firstPerCommitmentPoint: getPerCommitmentPoint(
					this._state.localPerCommitmentSeed,
					0n
				)
			}
		};
		// The type was resolved and validated at admission above; it is
		// always present here.
		this._state.channelType = Buffer.from(params.channelType!);

		// BOLT 2 v2: temporary_channel_id is derived from our revocation basepoint
		// (peer's zeroed), not random — so a spec-compliant peer routes our
		// open_channel2 and can return channel-assignable errors.
		this._state.temporaryChannelId = deriveV2TemporaryChannelId(
			params.localBasepoints.revocationBasepoint
		);

		const session = new DualFundingSession(
			true,
			this._state.temporaryChannelId,
			this._maxFundingSatoshis
		);
		const result = session.initiateOpen(params);
		if (!result.ok || !result.message) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to initiate open'
				}
			];
		}

		// max_htlc_value_in_flight_msat is advertised as configured, not
		// capacity-clamped (final v2 capacity is unknown here anyway; see
		// initiateOpen for why clamping is wrong in general). v2 params arrive
		// separately from the state config, so mirror the value from the BUILT
		// message into localConfig after the session accepted the open: our
		// inbound enforcement reads localConfig, and if it were lower than
		// what we advertised we would reject in-flight totals the peer is
		// entitled to send.
		this._state.localConfig.maxHtlcValueInFlightMsat =
			result.message.maxHtlcValueInFlightMsat;

		this._txAbortSent = false;
		this._state.dualFundingSession = session;
		this._state.state = ChannelState.DUAL_FUNDING_V2;

		return [
			sendMsg(
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(result.message)
			)
		];
	}

	/**
	 * Handle open_channel2 from remote (acceptor side).
	 * Returns the accept_channel2 response.
	 */
	handleOpenChannel2(
		msg: IOpenChannel2Message,
		localParams: IDualFundingParams
	): ChannelAction[] {
		if (this._state.state !== ChannelState.NONE) {
			// Deliberately LOCAL-only: this guard can only fire on a channel
			// that already has a life (a replayed or misrouted open), and a
			// wire error scoped to that id would cancel whatever the peer
			// still considers live. Every refusal of a FRESH open below is
			// wire-visible instead.
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected open_channel2' }
			];
		}

		// Every rejected inbound open_channel2 must reach the OPENER too
		// (BOLT 2 negotiation cancellation): a local error alone deletes our
		// half while the opener sits awaiting accept_channel2 forever. The
		// error is scoped to the id the opener used.
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(msg.channelId, reason);

		const acceptV2MaxHtlcErr = validateU64(
			localParams.maxHtlcValueInFlightMsat,
			'max_htlc_value_in_flight_msat'
		);
		if (acceptV2MaxHtlcErr) {
			return refuse(acceptV2MaxHtlcErr);
		}

		// Admission validation of the PROPOSED type before any state
		// mutation, echo or key adoption: a taproot or unrecognized type
		// would otherwise be echoed in ACCEPT_CHANNEL2 and die at the
		// commitment stage, and BOLT 2 makes the field REQUIRED on
		// open_channel2, so an absent type is refused too. The manager
		// validates against both init vectors; a raw Channel has none, so
		// the presence, structural and taproot rules still hold here.
		const v2TypeErr = validateV2ChannelType(msg.channelType ?? null);
		if (v2TypeErr) {
			return refuse(`open_channel2 refused: ${v2TypeErr}`);
		}
		// BOLT 2: an opener proposing scid_alias with the announce flag set
		// is asking for a pairing the spec forbids; refuse rather than
		// silently flip its intent.
		const aliasAnnounceErr = scidAliasAnnounceRefusal(
			msg.channelType ?? null,
			(msg.channelFlags & 0x01) !== 0
		);
		if (aliasAnnounceErr) {
			return refuse(`open_channel2 refused: ${aliasAnnounceErr}`);
		}

		this._state.fundingVersion = 2;
		this._state.commitmentFeeratePerkw = msg.commitmentFeeratePerkw;
		this._state.fundingLocktime = msg.locktime;

		// Same trusted-peer gate as the v1 path: a zero_conf channel type commits
		// us to minimum_depth 0, which we only extend to trusted peers. As on v1,
		// the flip is driven by the EXPLICIT channel type, never by trust-set
		// membership alone, and the accept_channel2 we build must advertise the
		// zero minimum_depth (BOLT 2 MUST for option_zeroconf).
		if (msg.channelType) {
			const proposedFlags = FeatureFlags.fromBuffer(msg.channelType);
			if (proposedFlags.hasFeature(Feature.ZERO_CONF)) {
				if (!this._state.trustedPeer) {
					return refuse(
						'Proposed zero_conf channel type requires a trusted peer'
					);
				}
				this._state.zeroConfEnabled = true;
				this._state.minimumDepth = 0;
				localParams = { ...localParams, minimumDepth: 0 };
			}
		}

		// accept_channel2 also carries a REAL first_per_commitment_point (see
		// initiateOpenV2): derive it from our seed rather than trusting the
		// basepoints struct's placeholder.
		localParams = {
			...localParams,
			localBasepoints: {
				...localParams.localBasepoints,
				firstPerCommitmentPoint: getPerCommitmentPoint(
					this._state.localPerCommitmentSeed,
					0n
				)
			}
		};
		const session = new DualFundingSession(
			false,
			this._state.temporaryChannelId,
			this._maxFundingSatoshis
		);
		const result = session.handleOpenChannel2(msg, localParams);
		if (!result.ok || !result.message) {
			return refuse(result.error || 'Failed to handle open_channel2');
		}

		// max_htlc_value_in_flight_msat is advertised as configured, not
		// capacity-clamped (a will_fund lease fee can still grow capacity
		// after this message; see initiateOpen). Mirror the value from the
		// BUILT accept_channel2 into localConfig after the session accepted
		// the open, so enforcement matches the advertisement exactly (see
		// initiateOpenV2).
		this._state.localConfig.maxHtlcValueInFlightMsat =
			result.message.maxHtlcValueInFlightMsat;

		this._txAbortSent = false;
		this._state.dualFundingSession = session;
		this._state.remoteBasepoints = session.getRemoteBasepoints();
		this._state.remoteCurrentPerCommitmentPoint = msg.firstPerCommitmentPoint;
		// BOLT 2 v2: the real channel_id (used from the first interactive-tx
		// message onward) is SHA256 over the two ordered revocation basepoints —
		// the opener's (from open_channel2) and ours. Both peers derive the same
		// value. temporary_channel_id (already adopted from the opener) stays the
		// tempChannels key until the open completes.
		this._state.channelId = deriveV2ChannelId(
			this._state.remoteBasepoints!.revocationBasepoint,
			this._state.localBasepoints.revocationBasepoint
		);
		// Record the negotiated channel type (validated at admission above,
		// which also made its PRESENCE mandatory per BOLT 2) so commitment
		// #0 is built with the same anchor dispatch on both sides.
		this._state.channelType = Buffer.from(msg.channelType!);
		this._state.state = ChannelState.DUAL_FUNDING_V2;

		// Dual funding v2: reconcile per-side balances from BOTH contributions.
		// The acceptor state was created as a stub (funding 0); now that we know the
		// opener's funding (msg) and our own (localParams), set the channel capacity
		// and each side's to_local balance. v2 has no push_msat, so each side's
		// balance is simply its own contribution. The commitment fee (paid by the
		// opener) is deducted later in the commitment builder.
		const openerFunding = msg.fundingSatoshis;
		const acceptorFunding = localParams.fundingSatoshis;
		this._state.fundingSatoshis = openerFunding + acceptorFunding;
		this._state.localBalanceMsat = acceptorFunding * 1000n;
		this._state.remoteBalanceMsat = openerFunding * 1000n;

		// Populate remoteConfig from the opener's open_channel2 so BOTH sides build
		// commitment #0 byte-identically. The opener PAYS the commitment fee, so the
		// acceptor's fee rate is the opener's commitment_feerate. Without this the
		// acceptor built at the default 253 sat/kw and the commitment_signed round
		// failed for any negotiated feerate. channel_reserve is not carried in v2
		// (both peers derive it, and it does not affect commitment bytes), so it is
		// derived for BOTH sides once the dust limits are in place.
		this._state.remoteConfig = {
			...this._state.remoteConfig,
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: msg.commitmentFeeratePerkw
		};
		this._deriveV2ChannelReserves();

		// Script-enforced lease and simple taproot channels are MUTUALLY-EXCLUSIVE
		// commitment types: LND has no taproot lease script (its taproot to_local and
		// second-level builders take no lease_expiry), so a leased taproot commitment
		// can be neither constructed interoperably nor swept. Refuse to enter the
		// lessor state on a taproot channel rather than build an unenforceable lease.
		// (The v2 acceptor doesn't stash channel_type on state yet, so key off the
		// open_channel2 message's channel_type — the value will_fund is signed over.)
		if (
			isTaprootChannel(msg.channelType ?? null) &&
			localParams.willFund &&
			msg.requestFunds
		) {
			return refuse(
				'Script-enforced lease is not supported on taproot channels'
			);
		}

		// Likewise anchors-only: the plain P2WPKH to_remote of a non-anchor
		// channel cannot carry the lease CLTV, so the lessor's balance on the
		// buyer's commitment would be unencumbered (the S-L.H4 escape).
		if (
			!isAnchorChannel(msg.channelType ?? null) &&
			localParams.willFund &&
			msg.requestFunds
		) {
			return refuse(
				'Script-enforced lease requires an anchor channel (option_anchors channel_type)'
			);
		}

		// Liquidity ads (bLIP-0051): if we (the seller) committed will_fund, the
		// buyer pays us the lease fee out of its initial balance — shift it from
		// the buyer (remote) to us (local). Reject if the buyer can't cover it.
		if (localParams.willFund && msg.requestFunds) {
			// Validate the buyer-supplied blockheight before it becomes our own
			// to_local CLTV lock: a bogus far-future or >= 500,000,000 value
			// (the CLTV height/timestamp boundary) would freeze OUR funds for
			// years. Require it within a sane window of our current tip.
			const bh = msg.requestFunds.blockheight;
			if (
				!Number.isInteger(bh) ||
				bh <= 0 ||
				bh >= 500_000_000 ||
				(this._currentBlockHeight > 0 &&
					(bh < this._currentBlockHeight - LEASE_BLOCKHEIGHT_PAST_TOLERANCE ||
						bh > this._currentBlockHeight + LEASE_BLOCKHEIGHT_FUTURE_TOLERANCE))
			) {
				return refuse(
					`Buyer lease blockheight ${bh} is out of the acceptable range`
				);
			}
			// Charge the proportional fee on what the lease actually funds:
			// min(our funding_satoshis, requested_sats). If we (the seller) fund
			// less than requested, billing the full request desyncs balances vs a
			// compliant peer that computes the fee on the amount truly provided.
			const leasedSats =
				localParams.fundingSatoshis < msg.requestFunds.requestedSats
					? localParams.fundingSatoshis
					: msg.requestFunds.requestedSats;
			const feeMsat =
				computeLeaseFeeSat(
					localParams.willFund.leaseRates,
					leasedSats,
					msg.fundingFeeratePerkw
				) * 1000n;
			// CLN's lease accounting (validated live): the buyer pays the fee
			// through the FUNDING TX — the funding output totals both
			// contributions PLUS the fee, our (seller) channel balance is
			// credited contribution + fee, and the buyer's balance stays its
			// full contribution. Mirrors the buyer side in handleAcceptChannel2.
			this._state.fundingSatoshis += feeMsat / 1000n;
			this._state.localBalanceMsat += feeMsat;
			this._state.leaseFeeSats = feeMsat / 1000n;
			// The lease fee grew the capacity the reserves above were derived from,
			// so re-derive. Nothing between the two points reads a reserve, and no
			// commitment is built from one, so the order is free.
			this._deriveV2ChannelReserves();
			// We are the lessor: our to_local is CSV-locked until the lease expires.
			this._state.leaseExpiry = computeLeaseExpiry(
				msg.requestFunds.blockheight
			);
			this._state.leaseCommitBlockheight = msg.requestFunds.blockheight;
			this._state.isLessor = true;
			// Remember the routing-fee caps we signed: while the lease is active we
			// MUST NOT advertise a channel_update exceeding them (the buyer paid
			// for capped fees).
			this._state.leaseChannelFeeMaxBaseMsat =
				localParams.willFund.leaseRates.channelFeeMaxBaseMsat;
			this._state.leaseChannelFeeMaxProportionalThousandths =
				localParams.willFund.leaseRates.channelFeeMaxProportionalThousandths;
		}

		// BOLT 2's initial-commitment MUST-fails, on the final split (any lease
		// fee is now folded into the balances above). Refusing here is what
		// keeps a channel whose commitment #0 has no spendable output from ever
		// being opened: it could not be broadcast, so neither side would have a
		// unilateral exit from the funding output.
		const viability = this._v2InitialCommitmentRefusal(
			this._state.localBalanceMsat / 1000n,
			this._state.remoteBalanceMsat / 1000n,
			false
		);
		if (viability) {
			return refuse(`open_channel2 refused: ${viability}`);
		}

		return [
			sendMsg(
				MessageType.ACCEPT_CHANNEL2,
				encodeAcceptChannel2Message(result.message)
			)
		];
	}

	/**
	 * Handle accept_channel2 from remote (opener side).
	 */
	handleAcceptChannel2(msg: IAcceptChannel2Message): ChannelAction[] {
		const refuse = (reason: string): ChannelAction[] =>
			refuseWithWireError(msg.channelId, reason);
		if (this._state.state !== ChannelState.DUAL_FUNDING_V2) {
			// Wire-visible, unlike the state guards of handleOpenChannel,
			// handleOpenChannel2, handleAcceptChannel, handleFundingCreated and
			// handleFundingSigned, and the asymmetry is deliberate (issue 393). Those
			// guards fire on a duplicated or late message for a negotiation that is
			// still live under the same id, so answering would cancel something
			// healthy. This one cannot: a v2 open stays DUAL_FUNDING_V2 for the whole
			// interactive-tx negotiation, so a duplicated accept_channel2 never
			// reaches here (session.handleAcceptChannel2 refuses it below, itself
			// wire-visibly), and once the record promotes the channel out of
			// tempChannels the manager answers "Unknown channel_id" without calling
			// us. What is left is a channel that is not a v2 open at all, most
			// plausibly a v1 SENT_OPEN answered with accept_channel2, and cancelling
			// that IS the right answer because the v1 open can never complete against
			// it.
			return refuse('Unexpected accept_channel2');
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			return refuse('No dual-funding session');
		}

		const result = session.handleAcceptChannel2(msg);
		if (!result.ok) {
			// The refusal must be WIRE-VISIBLE: a local error alone deletes
			// our half while the accepter sits waiting for tx_add_input
			// forever. The error is scoped to the id the peer used, so its
			// side cancels the open too.
			const reason = result.error || 'Failed to handle accept_channel2';
			return refuse(reason);
		}

		// BOLT 2: when the channel type is option_zeroconf the accepter MUST set
		// minimum_depth to zero. Surface the disagreement to BOTH sides: this
		// refusal ends the open, and a silent local exit would leave the
		// accepter waiting on a channel we no longer track.
		if (
			this._state.channelType &&
			FeatureFlags.fromBuffer(this._state.channelType).hasFeature(
				Feature.ZERO_CONF
			) &&
			msg.minimumDepth !== 0
		) {
			const reason = `zero_conf accept_channel2 must use minimum_depth 0, got ${msg.minimumDepth}`;
			return refuse(reason);
		}

		this._state.remoteBasepoints = session.getRemoteBasepoints();
		this._state.remoteCurrentPerCommitmentPoint = msg.firstPerCommitmentPoint;

		// BOLT 2 v2: derive the real channel_id from the two ordered revocation
		// basepoints now that the acceptor's is known (accept_channel2). Both peers
		// arrive at the same id; it is used from the first interactive-tx message.
		this._state.channelId = deriveV2ChannelId(
			this._state.localBasepoints.revocationBasepoint,
			this._state.remoteBasepoints!.revocationBasepoint
		);

		// Dual funding v2: fold the acceptor's contribution into the channel.
		// createOpenerState already set fundingSatoshis + localBalanceMsat to our
		// own funding; now add the acceptor's funding to the capacity and credit it
		// to their (remote) balance. v2 has no push_msat. The commitment fee (ours,
		// as opener) is deducted later in the commitment builder.
		const acceptorFunding = msg.fundingSatoshis;
		this._state.fundingSatoshis += acceptorFunding;
		this._state.remoteBalanceMsat += acceptorFunding * 1000n;

		// Populate remoteConfig from accept_channel2 so we build the acceptor's
		// commitment #0 with the acceptor's negotiated dust/delay. accept_channel2
		// carries no feerate (the opener sets it), so the acceptor's fee rate is our
		// own commitment feerate (which we build both commitments at). Neither side's
		// channel_reserve is carried in v2; both are derived once the dust limits are
		// in place.
		this._state.remoteConfig = {
			...this._state.remoteConfig,
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: this._state.commitmentFeeratePerkw
		};
		this._deriveV2ChannelReserves();

		// Liquidity ads (bLIP-0051): if the seller committed will_fund, we (the
		// buyer) pay the lease fee — shift it from us (local) to the seller
		// (remote). The seller is the lessor, so its to_local is CSV-locked until
		// lease_expiry; both sides record it so commitments agree.
		const requestFunds = session.getRequestFunds();
		// See handleOpenChannel2: leased + taproot is not a valid commitment type.
		// A well-behaved peer never sends will_fund on a taproot channel; refuse to
		// record a lease (and pay the fee) rather than expect an on-chain lease lock
		// the taproot commitment cannot carry. Key off the channel_type we proposed in
		// open_channel2 (the v2 opener doesn't stash it on state).
		if (
			isTaprootChannel(session.getOpenChannelType() ?? null) &&
			msg.willFund &&
			requestFunds
		) {
			return refuse(
				'Script-enforced lease is not supported on taproot channels'
			);
		}
		// Anchors-only for the same reason as handleOpenChannel2: a non-anchor
		// P2WPKH to_remote cannot carry the lessor's lease CLTV.
		if (
			!isAnchorChannel(session.getOpenChannelType() ?? null) &&
			msg.willFund &&
			requestFunds
		) {
			return refuse(
				'Script-enforced lease requires an anchor channel (option_anchors channel_type)'
			);
		}
		if (msg.willFund && requestFunds) {
			// M2 fund-safety: the seller must actually contribute at least the inbound
			// liquidity we are paying the lease fee for. verifyWillFund authenticates
			// the seller's signature but does NOT bind the funded amount, so without
			// this check an adversarial seller could return fundingSatoshis=0, pocket
			// the lease fee, and deliver no liquidity — an unconditional loss to us.
			if (msg.fundingSatoshis < requestFunds.requestedSats) {
				return refuse('Seller funded less than the requested lease amount');
			}
			const fundingFeeratePerkw =
				session.getLocalParams()?.fundingFeeratePerkw ?? 0;
			// Proportional fee is charged on min(seller funding, requested): a
			// seller that funds less than we requested is paid only for what it
			// actually provided (S-L/S-W MEDIUM). The verified min-funding check
			// above already guarantees fundingSatoshis >= requestedSats, so this
			// resolves to requestedSats in the honest path and simply refuses to
			// overpay if that ever changes.
			const leasedSats =
				msg.fundingSatoshis < requestFunds.requestedSats
					? msg.fundingSatoshis
					: requestFunds.requestedSats;
			const leaseFeeSat = computeLeaseFeeSat(
				msg.willFund.leaseRates,
				leasedSats,
				fundingFeeratePerkw
			);
			// H3 fund-safety: the seller's will_fund rates are self-signed and otherwise
			// bounded only by our whole balance, so an inflated leaseFeeBaseSat/
			// leaseFeeBasis could drain nearly all our funds. Bound the fee by the
			// maximum the buyer agreed to before requesting, carried locally as
			// maxLeaseRates. This ceiling must be buyer-chosen policy, never copied
			// from the seller's gossip ad (the seller controls both the ad and
			// will_fund, so a seller-derived ceiling bounds nothing). Refuse to pay
			// an unverified lease fee when no ceiling was set.
			const maxLeaseRates = session.getLocalParams()?.maxLeaseRates;
			if (!maxLeaseRates) {
				return refuse(
					'No maximum lease rates configured; refusing to pay an unverified lease fee'
				);
			}
			const maxLeaseFeeSat = computeLeaseFeeSat(
				maxLeaseRates,
				leasedSats,
				fundingFeeratePerkw
			);
			if (leaseFeeSat > maxLeaseFeeSat) {
				return refuse('Seller lease fee exceeds our accepted maximum');
			}
			// CLN's lease accounting (validated live): the buyer pays the fee
			// through the FUNDING TRANSACTION — the funding output must total
			// opener_funds + seller_funds + lease_fee, and the seller's CHANNEL
			// balance is credited seller_funds + lease_fee while the opener's
			// balance stays opener_funds. Deducting the fee from the opener's
			// channel balance instead (the old model) makes both the funding
			// output and the initial commitment disagree with the seller
			// ("Insufficiently funded funding tx" tx_abort from CLN).
			const feeMsat = leaseFeeSat * 1000n;
			this._state.fundingSatoshis += leaseFeeSat;
			this._state.remoteBalanceMsat += feeMsat;
			this._state.leaseFeeSats = leaseFeeSat;
			// Same as the seller side in handleOpenChannel2: the fee grew the
			// capacity the reserves were derived from.
			this._deriveV2ChannelReserves();
			this._state.leaseExpiry = computeLeaseExpiry(requestFunds.blockheight);
			this._state.leaseCommitBlockheight = requestFunds.blockheight;
		}

		// The same initial-commitment MUST-fails as the acceptor side, on the
		// final split: we are the opener here, so the commitment fee is ours.
		const viability = this._v2InitialCommitmentRefusal(
			this._state.localBalanceMsat / 1000n,
			this._state.remoteBalanceMsat / 1000n,
			true
		);
		if (viability) {
			return refuse(`accept_channel2 refused: ${viability}`);
		}

		return [];
	}

	/**
	 * Add a local input during interactive TX construction (v2 channel).
	 */
	addTxInput(input: IInteractiveTxInput): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot add TX input: wrong state'
				}
			];
		}

		const result = session.addInput(input);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to add input'
				}
			];
		}

		const msg: ITxAddInputMessage = {
			channelId: this._v2ChannelId(),
			serialId: input.serialId,
			prevTx: input.prevTx || Buffer.alloc(0),
			prevTxVout: input.prevOutputIndex,
			sequence: input.sequence
		};

		return [sendMsg(MessageType.TX_ADD_INPUT, encodeTxAddInputMessage(msg))];
	}

	/**
	 * Is an interactive-tx negotiation for a splice currently active? When true,
	 * the tx_* interactive messages belong to the splice session rather than a
	 * dual-funding session.
	 */
	private _spliceTxNegotiationActive(): boolean {
		return (
			this._spliceSession !== null &&
			this._spliceSession.getState() === SpliceState.TX_NEGOTIATION
		);
	}

	/**
	 * Handle tx_add_input from peer during v2 opening.
	 */
	handleTxAddInput(msg: ITxAddInputMessage): ChannelAction[] {
		// Splicing reuses the interactive-tx protocol. If a splice negotiation is
		// in progress, route the peer's input into the splice session.
		if (this._spliceTxNegotiationActive()) {
			// For the shared (existing funding) input the prevout txid arrives in the
			// shared_input_txid TLV with an empty prevTx; use it so both sides build
			// the identical transaction. For ordinary inputs the txid comes from the
			// provided prevTx.
			//
			// The shared input MUST be the channel's own funding outpoint: a
			// mismatched shared input would make each side sign commitments
			// against a different splice txid. Fail the negotiation with tx_abort
			// (the existing channel is unaffected) rather than a channel error.
			if (msg.sharedInputTxid) {
				if (
					!this._state.fundingTxid ||
					!msg.sharedInputTxid.equals(this._state.fundingTxid) ||
					msg.prevTxVout !== this._state.fundingOutputIndex
				) {
					return [
						this._txAbort(
							this._state.channelId!,
							'splice shared input does not match the channel funding outpoint'
						),
						...this.abortSplice(
							'peer splice shared input does not match the channel funding outpoint'
						)
					];
				}
			}
			let prevTxid = Buffer.alloc(32);
			if (msg.sharedInputTxid) {
				prevTxid = Buffer.from(msg.sharedInputTxid);
			} else if (msg.prevTx && msg.prevTx.length >= 32) {
				try {
					prevTxid = extractTxidFromPrevTx(msg.prevTx);
				} catch {
					// Unparseable prev_tx: rejected by the builder's prevtx checks.
				}
			}
			const input: IInteractiveTxInput = {
				serialId: msg.serialId,
				prevTxid,
				prevOutputIndex: msg.prevTxVout,
				sequence: msg.sequence,
				prevTx: msg.prevTx,
				prevTxVout: msg.prevTxVout,
				isShared: !!msg.sharedInputTxid
			};
			const err = this._spliceSession!.addPeerInput(input);
			if (err) {
				// BOLT 2: an invalid tx_add_input fails the NEGOTIATION. For a
				// splice that means tx_abort + unwind; the channel keeps operating
				// on the existing funding output.
				return [
					this._txAbort(this._state.channelId!, err),
					...this.abortSplice(err),
					{ type: ChannelActionType.ERROR, message: `splice aborted: ${err}` }
				];
			}
			return this._driveSplice();
		}

		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected tx_add_input' }
			];
		}

		// Extract the real prevout txid: leaving it zeroed made every peer input
		// share the same prevout key, so checkDuplicatePrevouts collapsed two
		// distinct inputs with the same vout into a "duplicate" (S-2.H4).
		let prevTxid = Buffer.alloc(32);
		if (msg.prevTx && msg.prevTx.length >= 32) {
			try {
				prevTxid = extractTxidFromPrevTx(msg.prevTx);
			} catch {
				// Unparseable prev_tx: rejected by the builder's prevtx checks.
			}
		}
		const input: IInteractiveTxInput = {
			serialId: msg.serialId,
			prevTxid,
			prevOutputIndex: msg.prevTxVout,
			sequence: msg.sequence,
			prevTx: msg.prevTx,
			prevTxVout: msg.prevTxVout
		};

		const result = session.addPeerInput(input);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle peer input'
				}
			];
		}

		// Our turn: contribute our own inputs/change when we accepted with a
		// contribution (lease selling); no-op otherwise. A rollback record
		// retained through an accepted RBF stays retained here: it is only
		// replaced, atomically, by the new attempt's record at its
		// commitment persist (_syncV2InFlight).
		return this._driveDualFunding();
	}

	/**
	 * Add a local output during interactive TX construction (v2 channel).
	 */
	addTxOutput(output: IInteractiveTxOutput): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot add TX output: wrong state'
				}
			];
		}

		const result = session.addOutput(output);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to add output'
				}
			];
		}

		const msg: ITxAddOutputMessage = {
			channelId: this._v2ChannelId(),
			serialId: output.serialId,
			amountSats: output.amountSats,
			scriptPubkey: output.scriptPubkey
		};

		return [sendMsg(MessageType.TX_ADD_OUTPUT, encodeTxAddOutputMessage(msg))];
	}

	/**
	 * Handle tx_add_output from peer during v2 opening.
	 */
	handleTxAddOutput(msg: ITxAddOutputMessage): ChannelAction[] {
		if (this._spliceTxNegotiationActive()) {
			// Peer outputs must respect the negotiated dust floor, not a flat 546:
			// both sides' commitment dust limits are known on an active channel.
			this._spliceSession!.getTxBuilder()?.setDustLimit(
				this._state.localConfig.dustLimitSatoshis >
					this._state.remoteConfig.dustLimitSatoshis
					? this._state.localConfig.dustLimitSatoshis
					: this._state.remoteConfig.dustLimitSatoshis
			);
			const output: IInteractiveTxOutput = {
				serialId: msg.serialId,
				amountSats: msg.amountSats,
				scriptPubkey: msg.scriptPubkey
			};
			const err = this._spliceSession!.addPeerOutput(output);
			if (err) {
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			return this._driveSplice();
		}

		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected tx_add_output' }
			];
		}

		// Negotiated dust floor from open_channel2/accept_channel2.
		const localDust = session.getLocalParams()?.dustLimitSatoshis ?? 0n;
		const remoteDust = session.isInitiator()
			? session.getAcceptMsg()?.dustLimitSatoshis ?? 0n
			: session.getOpenMsg()?.dustLimitSatoshis ?? 0n;
		session
			.getTxBuilder()
			?.setDustLimit(localDust > remoteDust ? localDust : remoteDust);

		const output: IInteractiveTxOutput = {
			serialId: msg.serialId,
			amountSats: msg.amountSats,
			scriptPubkey: msg.scriptPubkey
		};

		const result = session.addPeerOutput(output);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle peer output'
				}
			];
		}

		// Our turn (see handleTxAddInput).
		return this._driveDualFunding();
	}

	/**
	 * Remove a local input during interactive TX construction.
	 */
	removeTxInput(serialId: bigint): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot remove TX input: wrong state'
				}
			];
		}

		const result = session.removeInput(serialId);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to remove input'
				}
			];
		}

		const msg: ITxRemoveInputMessage = {
			channelId: this._v2ChannelId(),
			serialId
		};

		return [
			sendMsg(MessageType.TX_REMOVE_INPUT, encodeTxRemoveInputMessage(msg))
		];
	}

	/**
	 * Handle tx_remove_input from peer.
	 */
	handleTxRemoveInput(msg: ITxRemoveInputMessage): ChannelAction[] {
		if (this._spliceTxNegotiationActive()) {
			const err = this._spliceSession!.removePeerInput(msg.serialId);
			if (err) {
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			return [];
		}

		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected tx_remove_input' }
			];
		}

		const result = session.removePeerInput(msg.serialId);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle remove input'
				}
			];
		}

		return [];
	}

	/**
	 * Remove a local output during interactive TX construction.
	 */
	removeTxOutput(serialId: bigint): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot remove TX output: wrong state'
				}
			];
		}

		const result = session.removeOutput(serialId);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to remove output'
				}
			];
		}

		const msg: ITxRemoveOutputMessage = {
			channelId: this._v2ChannelId(),
			serialId
		};

		return [
			sendMsg(MessageType.TX_REMOVE_OUTPUT, encodeTxRemoveOutputMessage(msg))
		];
	}

	/**
	 * Handle tx_remove_output from peer.
	 */
	handleTxRemoveOutput(msg: ITxRemoveOutputMessage): ChannelAction[] {
		if (this._spliceTxNegotiationActive()) {
			const err = this._spliceSession!.removePeerOutput(msg.serialId);
			if (err) {
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			return [];
		}

		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected tx_remove_output'
				}
			];
		}

		const result = session.removePeerOutput(msg.serialId);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle remove output'
				}
			];
		}

		return [];
	}

	/**
	 * Signal tx_complete during interactive TX construction.
	 */
	/**
	 * Register the wallet inputs funding OUR side of a v2 open we ACCEPT (the
	 * lessor's contribution on a bLIP-0051 lease). The interactive-tx drive
	 * then contributes them automatically on our turns, and tx_signatures
	 * signs them via each input's wallet closure.
	 */
	setDualFundingContribution(
		inputs: ISpliceWalletInput[],
		changeScript: Buffer,
		contributionSats: bigint,
		feeratePerKw: number
	): void {
		this._dualFundingContribution = {
			inputs,
			changeScript,
			contributionSats,
			feeratePerKw
		};
		this._dualFundingContribs = null;
		this._dualFundingContribIndex = 0;
	}

	/**
	 * Derive the ordered interactive-tx contributions for our acceptor share:
	 * each wallet input, then a change output (walletTotal - contribution -
	 * our interactive-tx fee share). BOLT 2: each side pays the feerate over
	 * the weight of what IT adds — for us that is the P2WPKH inputs and the
	 * change output (the opener pays for the shared funding output).
	 */
	private _computeDualFundingContributions(): string | null {
		const session = this._state.dualFundingSession;
		const c = this._dualFundingContribution;
		if (!session || !c) return 'No dual-funding contribution registered';
		const initiator = session.isInitiator();

		// A zero contribution (a plain v2 accept: no inputs, no funding share)
		// adds nothing to the transaction, so it owes no fee and produces no
		// outputs — the drive goes straight to tx_complete on our turns.
		// Without this early exit the change derivation below reserves the
		// change-output cushion against inputs that do not exist and fails
		// every plain accept as "underfunded".
		if (!initiator && c.inputs.length === 0 && c.contributionSats === 0n) {
			this._dualFundingContribs = [];
			return null;
		}

		// BOLT 2: each side pays the feerate over the weight of what IT adds;
		// the initiator additionally pays for the common transaction fields and
		// the shared funding output. Cushioned figures — see
		// dualFundingContributionWeight, which the funding provider's max-open
		// quote shares so a max contribution nets out to exactly zero change.
		const feeSats = spliceFeeSats(
			dualFundingContributionWeight(c.inputs.length, initiator),
			c.feeratePerKw
		);

		let walletTotal = 0n;
		this._dualFundingContribs = [];
		this._dualFundingContribIndex = 0;
		for (const w of c.inputs) {
			walletTotal += w.value;
			this._dualFundingContribs.push({
				kind: 'input',
				input: {
					serialId: session.nextSerialId(),
					prevTxid: extractTxidFromPrevTx(w.prevTx),
					prevOutputIndex: w.prevOutputIndex,
					sequence: w.sequence,
					prevTx: w.prevTx,
					prevTxVout: w.prevOutputIndex
				}
			});
		}

		// BOLT 2: the initiator adds the shared funding output, sized to the
		// FULL negotiated capacity — both sides' funding plus any lease fee,
		// which handleAcceptChannel2 has already folded into fundingSatoshis.
		if (initiator) {
			if (!this._state.remoteBasepoints) {
				return 'Cannot build funding output before accept_channel2';
			}
			const taproot = isTaprootChannel(session.getOpenChannelType() ?? null);
			let fundingSpk: Buffer;
			if (taproot) {
				fundingSpk = createTaprootFundingScript(
					this._state.localBasepoints.fundingPubkey,
					this._state.remoteBasepoints.fundingPubkey
				).p2trOutput;
			} else {
				fundingSpk = createFundingScript(
					this._state.localBasepoints.fundingPubkey,
					this._state.remoteBasepoints.fundingPubkey
				).p2wshOutput;
			}
			this._dualFundingContribs.push({
				kind: 'output',
				output: {
					serialId: session.nextSerialId(),
					amountSats: this._state.fundingSatoshis,
					scriptPubkey: fundingSpk
				}
			});
		}

		const changeSats = walletTotal - c.contributionSats - feeSats;
		if (changeSats < 0n) {
			return `Dual-funding contribution underfunded: inputs ${walletTotal} < contribution ${c.contributionSats} + fee ${feeSats}`;
		}
		// A change output below the interactive-tx dust floor cannot be added at
		// all: our own builder rejects it on the way out and the peer rejects it
		// on the way in, killing an otherwise fundable open. It becomes extra fee
		// instead. The floor is the NEGOTIATED one, never the 294-sat P2WPKH
		// figure: selection covers exactly contribution + fee, so change lands in
		// the 295..545 band routinely rather than exceptionally (issue #380).
		if (changeSats >= this._v2InteractiveTxDustFloor(session)) {
			this._dualFundingContribs.push({
				kind: 'output',
				output: {
					serialId: session.nextSerialId(),
					amountSats: changeSats,
					scriptPubkey: c.changeScript
				}
			});
		}
		return null;
	}

	/**
	 * The dust floor an output WE add to a v2 open funding transaction must
	 * clear.
	 *
	 * Mirrors what InteractiveTxBuilder enforces on every tx_add_output, ours
	 * included: the 546-sat interactive-tx floor, raised to whichever side
	 * negotiated the larger commitment dust limit (the same pair
	 * handleTxAddOutput feeds to setDustLimit). Using anything lower means
	 * emitting an output the peer must reject.
	 */
	private _v2InteractiveTxDustFloor(session: DualFundingSession): bigint {
		const localDust = session.getLocalParams()?.dustLimitSatoshis ?? 0n;
		const remoteDust = session.isInitiator()
			? session.getAcceptMsg()?.dustLimitSatoshis ?? 0n
			: session.getOpenMsg()?.dustLimitSatoshis ?? 0n;
		let floor = DUST_LIMIT_SATS;
		if (localDust > floor) floor = localDust;
		if (remoteDust > floor) floor = remoteDust;
		return floor;
	}

	/**
	 * Whether the registered wallet contribution can still cover itself at
	 * the given feerate: the same arithmetic _computeDualFundingContributions
	 * applies (inputs must cover contribution + our interactive-tx fee
	 * share), evaluated without touching the session or the derived list.
	 * Null when affordable, when no contribution is registered (legacy
	 * caller-driven flow), or for a plain zero accept, which owes no fee.
	 *
	 * `proposed` prices a contribution the channel has not adopted yet (an RBF
	 * that changes our share, funded by the registered inputs plus whatever
	 * top-up the caller selected), so the request can be refused before it
	 * reaches the wire. Nothing is mutated either way.
	 */
	private _dualFundingAffordabilityError(
		feeratePerKw: number,
		proposed?: { contributionSats: bigint; inputs: ISpliceWalletInput[] }
	): string | null {
		const session = this._state.dualFundingSession;
		const c = this._dualFundingContribution;
		if (!session || !c) return null;
		const inputs = proposed?.inputs ?? c.inputs;
		const contributionSats = proposed?.contributionSats ?? c.contributionSats;
		const initiator = session.isInitiator();
		if (!initiator && inputs.length === 0 && contributionSats === 0n) {
			return null;
		}
		const feeSats = spliceFeeSats(
			dualFundingContributionWeight(inputs.length, initiator),
			feeratePerKw
		);
		let walletTotal = 0n;
		for (const w of inputs) {
			walletTotal += w.value;
		}
		if (walletTotal - contributionSats - feeSats < 0n) {
			return `wallet contribution cannot cover feerate ${feeratePerKw}: inputs ${walletTotal} < contribution ${contributionSats} + fee ${feeSats}`;
		}
		return null;
	}

	/**
	 * What an RBF that changes our funding contribution to `newFundingSatoshis`
	 * would need from the wallet: `topUpSats` is 0 when the registered inputs
	 * already cover it (any decrease, and increases with enough headroom),
	 * otherwise the shortfall the caller must select and pledge before
	 * requesting the RBF.
	 *
	 * Read-only, and deliberately outside initiateTxRbf: the node layer needs
	 * the answer BEFORE it decides whether the request can be served
	 * synchronously or has to go through the wallet first.
	 *
	 * The shortfall is priced over the inputs registered NOW, so it covers the
	 * contribution's fixed fee terms but not the weight of the top-up coins the
	 * wallet has yet to pick. Those are the selector's half of the split:
	 * selectDualFundingInputs is called with topUp = true and charges only
	 * dualFundingTopUpWeight(k), the marginal per-input weight. The two halves
	 * add up to exactly what initiateTxRbf then re-checks over the combined set,
	 * to within the one sat that separates fee(a) + fee(b) from fee(a + b).
	 * Pricing the top-up as a whole contribution instead double-counts the fixed
	 * terms and refuses a raise the wallet can afford (issue #380).
	 */
	quoteV2RbfContributionChange(
		newFundingSatoshis: bigint,
		feeratePerKw: number
	): { ok: true; topUpSats: bigint } | { ok: false; error: string } {
		const c = this._dualFundingContribution;
		if (!c) {
			return {
				ok: false,
				error:
					'cannot change the funding contribution: no wallet contribution is registered for this open'
			};
		}
		if (this._state.leaseFeeSats !== undefined) {
			return {
				ok: false,
				error:
					'changing the funding contribution of a leased v2 open is not supported'
			};
		}
		if (newFundingSatoshis <= 0n) {
			return {
				ok: false,
				error: 'RBF funding contribution must be greater than 0'
			};
		}
		let walletTotal = 0n;
		for (const w of c.inputs) {
			walletTotal += w.value;
		}
		const required =
			newFundingSatoshis +
			spliceFeeSats(
				dualFundingContributionWeight(c.inputs.length, true),
				feeratePerKw
			);
		return {
			ok: true,
			topUpSats: required > walletTotal ? required - walletTotal : 0n
		};
	}

	/**
	 * Interactive-tx drive for a v2 open with a registered contribution: on
	 * each of our turns send the next wallet input / funding or change output,
	 * then tx_complete (re-sent whenever the peer keeps adding, exactly like
	 * the splice acceptor drive). Works for both roles: the acceptor's share
	 * is inputs + change (lease selling), the initiator's additionally carries
	 * the shared funding output. Without a registered contribution this is a
	 * no-op and the legacy caller-driven flow applies.
	 */
	private _driveDualFunding(): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (
			!session ||
			!this._dualFundingContribution ||
			session.getState() !== DualFundingState.TX_NEGOTIATION
		) {
			return [];
		}

		if (!this._dualFundingContribs) {
			const err = this._computeDualFundingContributions();
			if (err) return this._abortV2Negotiation(err);
		}

		if (this._dualFundingContribIndex < this._dualFundingContribs!.length) {
			const c = this._dualFundingContribs![this._dualFundingContribIndex++];
			if (c.kind === 'input') {
				const result = session.addInput(c.input);
				if (!result.ok) {
					return this._abortV2Negotiation(
						result.error || 'Failed to add contribution input'
					);
				}
				const msg: ITxAddInputMessage = {
					channelId: this._v2ChannelId(),
					serialId: c.input.serialId,
					prevTx: c.input.prevTx || Buffer.alloc(0),
					prevTxVout: c.input.prevOutputIndex,
					sequence: c.input.sequence
				};
				return [
					sendMsg(MessageType.TX_ADD_INPUT, encodeTxAddInputMessage(msg))
				];
			}
			const result = session.addOutput(c.output);
			if (!result.ok) {
				return this._abortV2Negotiation(
					result.error || 'Failed to add contribution output'
				);
			}
			const outMsg: ITxAddOutputMessage = {
				channelId: this._v2ChannelId(),
				serialId: c.output.serialId,
				amountSats: c.output.amountSats,
				scriptPubkey: c.output.scriptPubkey
			};
			return [
				sendMsg(MessageType.TX_ADD_OUTPUT, encodeTxAddOutputMessage(outMsg))
			];
		}

		// Contributions exhausted: (re)send tx_complete whenever the builder is
		// back in a state where our completion is outstanding.
		const builderState = session.getTxBuilder()?.getState();
		if (
			builderState === InteractiveTxState.COLLECTING ||
			builderState === InteractiveTxState.RECEIVED_COMPLETE
		) {
			return this.sendTxComplete();
		}
		return [];
	}

	/**
	 * Kick off the INITIATOR's interactive-tx contribution once a contribution
	 * has been registered (setDualFundingContribution) after accept_channel2.
	 * BOLT 2: the initiator sends the first tx_add_input, so nothing moves
	 * until this runs; the peer's replies then pull the rest of the
	 * contribution out turn by turn via the handleTx* paths.
	 */
	beginDualFundingContribution(): ChannelAction[] {
		return this._driveDualFunding();
	}

	sendTxComplete(): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot send tx_complete: wrong state'
				}
			];
		}

		const result = session.markComplete();
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to mark complete'
				}
			];
		}

		// If both sides are now complete, move to AWAITING_TX_SIGNATURES
		if (session.getState() === DualFundingState.AWAITING_TX_SIGNATURES) {
			// Audit the negotiated tx before signing anything for it (S-2.M4).
			const invalid =
				this._validateNegotiatedInteractiveTx('v2') ??
				this._v2RbfAttemptAuditError();
			if (invalid) {
				return this._unwindV2NegotiationOrRollback(invalid);
			}
			this._state.state = ChannelState.AWAITING_TX_SIGNATURES;
		}

		// BOLT 2 v2: once both sides have completed, the commitment_signed
		// exchange starts (before any tx_signatures). Ours goes out right after
		// our tx_complete on the wire. A commitment FAILURE must replace the
		// batch entirely: sending the tx_complete anyway would push the peer
		// over its own commitment point for a round we are about to unwind,
		// leaving it durably on the replacement while we roll back.
		const commitment = this._maybeSendV2Commitment();
		if (commitment.some((a) => a.type === ChannelActionType.ERROR)) {
			return commitment;
		}
		return [
			sendMsg(
				MessageType.TX_COMPLETE,
				encodeTxCompleteMessage({
					channelId: this._v2ChannelId()
				})
			),
			...commitment
		];
	}

	/**
	 * Handle tx_complete from peer.
	 */
	handleTxComplete(): ChannelAction[] {
		if (this._spliceTxNegotiationActive()) {
			const err = this._spliceSession!.handlePeerTxComplete();
			if (err) {
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			// Our turn: send the next contribution, or our own tx_complete once we
			// have nothing left to add. When both sides have completed the session
			// moves to AWAITING_TX_SIGNATURES, at which point we build the splice tx
			// and send commitment_signed for the new outpoint (BOLT 2 splicing: the
			// commitment_signed round precedes tx_signatures).
			const driveActions = this._driveSplice();
			if (
				this._spliceSession!.getState() === SpliceState.AWAITING_TX_SIGNATURES
			) {
				// Both sides complete: audit the negotiated tx before signing
				// anything for it (S-2.M4). An unacceptable tx fails the
				// NEGOTIATION, not the channel: tx_abort + unwind (nothing is
				// signed yet), mirroring the tx_add_input refusal arm. A bare
				// ERROR would leave both sides parked in a dead splice. The
				// peer's mid-splice commitment_signed may already be in flight
				// behind its tx_complete; the ignore window absorbs it.
				const invalid = this._validateNegotiatedInteractiveTx('splice');
				if (invalid) {
					this._spliceAbortIgnoreCommitment = true;
					return [
						this._txAbort(this._state.channelId!, invalid),
						...this.abortSplice(invalid),
						{
							type: ChannelActionType.ERROR,
							message: `splice aborted: ${invalid}`
						}
					];
				}
			}
			return [...driveActions, ...this._maybeSendSpliceCommitment()];
		}

		const session = this._state.dualFundingSession;
		if (!session || session.getState() !== DualFundingState.TX_NEGOTIATION) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected tx_complete' }
			];
		}

		const result = session.handlePeerComplete();
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle peer complete'
				}
			];
		}

		// If both sides are now complete, move to AWAITING_TX_SIGNATURES and
		// start the commitment_signed exchange (BOLT 2 v2: it precedes
		// tx_signatures). A retained rollback record survives right up to
		// _maybeSendV2Commitment's record creation, which replaces it
		// atomically in the same persist (_syncV2InFlight); an audit failure
		// instead rolls the renegotiation back to it.
		if (session.getState() === DualFundingState.AWAITING_TX_SIGNATURES) {
			// Audit the negotiated tx before signing anything for it (S-2.M4).
			// A shared-deterministic audit failure is safe to roll back: the
			// peer runs the same audit over the same tx before ITS
			// commitment, so it cannot have committed a tx we refuse.
			const invalid =
				this._validateNegotiatedInteractiveTx('v2') ??
				this._v2RbfAttemptAuditError();
			if (invalid) {
				return this._unwindV2NegotiationOrRollback(invalid);
			}
			this._state.state = ChannelState.AWAITING_TX_SIGNATURES;
			// The completing tx_complete was RECEIVED: its sender completes
			// and commits in one batch, so its replacement commitment may
			// already be queued behind this very message. A local signer
			// failure here must therefore be terminal, never a rollback to
			// an attempt the peer may have durably left.
			return this._maybeSendV2Commitment(true);
		}

		// Peer completed but we have not: contribute our remaining
		// inputs/change (or answer with our tx_complete) when a contribution
		// is registered; legacy caller-driven flow otherwise.
		return this._driveDualFunding();
	}

	/**
	 * Deterministically assemble the negotiated v2 funding transaction and
	 * locate the 2-of-2 funding output. Both peers must know the funding
	 * outpoint BEFORE any signatures are exchanged: the commitment_signed round
	 * that precedes tx_signatures signs commitment #0 spending this outpoint.
	 * Also the fund-safety check that the negotiated tx actually contains the
	 * funding output carrying the full negotiated capacity — returns null (the
	 * caller errors) when it does not.
	 */
	/**
	 * The channel_id to stamp on v2 (dual-funding) wire messages. BOLT 2 uses the
	 * temporary_channel_id only for open_channel2/accept_channel2 (built by the
	 * DualFundingSession); every message from the first interactive-tx message
	 * onward uses the real channel_id, derived from both revocation basepoints and
	 * set as state.channelId once accept_channel2 is exchanged. Before that (the
	 * opener aborting between open and accept) it falls back to the temp id.
	 */
	private _v2ChannelId(): Buffer {
		return this._state.channelId ?? this._state.temporaryChannelId;
	}

	/**
	 * BOLT 2 receive-side checks on a fully negotiated interactive tx (v2
	 * funding or splice), run when the negotiation completes: standardness
	 * weight cap, and — when every input's value is known from its prev_tx —
	 * that the peer's inputs cover its outputs plus its positive contribution
	 * and that the paid fee meets the negotiated feerate (S-2.M4). The shared
	 * splice input (no prev_tx; worth the pre-splice capacity) belongs to the
	 * splice initiator; the shared funding output belongs to whoever added it.
	 * Inputs with unparseable prev_tx skip the funds/fee checks (their strict
	 * enforcement is S-2.H3).
	 */
	private _validateNegotiatedInteractiveTx(
		kind: 'v2' | 'splice'
	): string | null {
		let inputs: IInteractiveTxInput[];
		let outputs: IInteractiveTxOutput[];
		let weAreInitiator: boolean;
		let remoteContributionSats: bigint;
		let feeratePerKw: number;
		if (kind === 'splice') {
			const session = this._spliceSession;
			const builder = session?.getTxBuilder();
			if (!session || !builder) return null;
			inputs = builder.getInputs();
			outputs = builder.getOutputs();
			weAreInitiator = session.isInitiator();
			remoteContributionSats = session.getRemoteRelativeSatoshis();
			feeratePerKw = session.getFundingFeeratePerkw();
		} else {
			const session = this._state.dualFundingSession;
			const builder = session?.getTxBuilder();
			if (!session || !builder) return null;
			inputs = builder.getInputs();
			outputs = builder.getOutputs();
			weAreInitiator = session.isInitiator();
			remoteContributionSats = session.getRemoteFundingSatoshis();
			feeratePerKw =
				session.getLocalParams()?.fundingFeeratePerkw ??
				session.getOpenMsg()?.fundingFeeratePerkw ??
				0;
		}

		// The shared 2-of-2 funding output (the one paying the new/negotiated
		// funding script) is excluded from per-side output sums: each side's
		// stake in it is its contribution.
		let fundingScript: Buffer | null = null;
		if (this._state.remoteBasepoints) {
			try {
				const localPub =
					kind === 'splice'
						? this._spliceSession!.getLocalFundingPubkey()
						: this._state.localBasepoints.fundingPubkey;
				const remotePub =
					kind === 'splice'
						? this._spliceSession!.getRemoteFundingPubkey() ??
						  this._state.remoteBasepoints.fundingPubkey
						: this._state.remoteBasepoints.fundingPubkey;
				fundingScript = createFundingScript(localPub, remotePub).p2wshOutput;
			} catch {
				fundingScript = null;
			}
		}

		let weight = SPLICE_TX_BASE_WEIGHT;
		let remoteInputSats = 0n;
		let remoteOutputSats = 0n;
		let totalInSats = 0n;
		let totalOutSats = 0n;
		let valuesKnown = true;
		for (const input of inputs) {
			const remoteOwned = (input.serialId % 2n === 0n) !== weAreInitiator;
			const isShared =
				kind === 'splice' && (!input.prevTx || input.prevTx.length === 0);
			if ((kind === 'v2' || (kind === 'splice' && remoteOwned)) && !isShared) {
				// Witnesses can only be VERIFIED for P2WPKH and P2TR key-spend
				// prevouts; every other type would have to be accepted on
				// shape alone. Refuse the negotiation HERE, before the
				// commitment round signs anything for this transaction, rather
				// than at tx_signatures when signatures may already be out.
				// Splice checks REMOTE inputs only: our own splice-in inputs
				// are signed by the wallet's own closures (any script type)
				// and never pass through our witness validator.
				const unsupported = this._v2CheckInputSpendable(input);
				if (unsupported) return unsupported;
			}
			weight += isShared
				? SHARED_FUNDING_INPUT_WEIGHT
				: auditMinInputWeightWu(input);
			if (isShared) {
				// Pre-splice capacity rolls over; it is nobody's new contribution.
				totalInSats += this._state.fundingSatoshis;
				continue;
			}
			const value = interactiveInputValueSats(input);
			if (value === null) {
				valuesKnown = false;
				continue;
			}
			totalInSats += value;
			if (remoteOwned) remoteInputSats += value;
		}
		for (const output of outputs) {
			const remoteOwned = (output.serialId % 2n === 0n) !== weAreInitiator;
			const isShared =
				fundingScript !== null && output.scriptPubkey.equals(fundingScript);
			weight += outputWeight(output.scriptPubkey.length);
			totalOutSats += output.amountSats;
			if (remoteOwned && !isShared) remoteOutputSats += output.amountSats;
		}

		let audit: string | null;
		if (!valuesKnown) {
			// Cannot audit funds/fees without input values; still enforce weight.
			audit =
				weight > 400_000
					? `Transaction weight ${weight} exceeds 400000 WU`
					: null;
		} else {
			audit = validateCompletedInteractiveTx({
				remoteInputSats,
				remoteOutputSats,
				remoteContributionSats,
				feeSats: totalInSats - totalOutSats,
				weight,
				feeratePerKw
			});
		}
		if (audit) return audit;
		// The BOLT 2 splice reserve rule (issue #423) needs no input values, so
		// it runs whether or not every prev_tx parsed, and after the existing
		// refusals so their reason strings win when a tx trips more than one
		// check.
		return kind === 'splice'
			? this._spliceBelowReserveRefusal(outputs, fundingScript, weAreInitiator)
			: null;
	}

	/**
	 * BOLT 2 tx_complete (splice): the negotiation MUST fail when either side
	 * has added an output other than the new channel funding output and that
	 * side's post-splice balance is below the channel reserve priced at the NEW
	 * capacity (issue #423). Being below reserve on its own is fine; a side
	 * taking funds OUT of the channel must end up meeting it. Runs at the
	 * tx_complete audit, BEFORE the splice tx is built (_spliceTx is set later
	 * by _maybeSendSpliceCommitment), so the split is derived with
	 * _splicedState's arithmetic from the session and the negotiated outputs.
	 * The peer's side is judged against v2ReserveWeEnforce (never above what a
	 * conforming peer computes for itself, so an honest spec-legal splice is
	 * never aborted) and our own against v2ReserveWeKeep (the most a conforming
	 * peer may enforce on us), both derived from the new capacity alone: the
	 * stored reserve is a preflight concern, not a wire-audit one.
	 */
	private _spliceBelowReserveRefusal(
		outputs: IInteractiveTxOutput[],
		fundingScript: Buffer | null,
		weAreInitiator: boolean
	): string | null {
		const session = this._spliceSession;
		if (!session || !fundingScript) return null;
		let newCapacity: bigint | null = null;
		let weAdded = false;
		let theyAdded = false;
		for (const output of outputs) {
			if (output.scriptPubkey.equals(fundingScript)) {
				if (newCapacity === null) newCapacity = output.amountSats;
				continue;
			}
			if ((output.serialId % 2n === 0n) !== weAreInitiator) theyAdded = true;
			else weAdded = true;
		}
		// No funding output (the commitment step errors on that) or no
		// non-funding output on either side: the rule does not arm.
		if (newCapacity === null || (!weAdded && !theyAdded)) return null;
		const feeFromChannelSats =
			this._state.fundingSatoshis +
			session.getNetCapacityChange() -
			newCapacity;
		const myFeeMsat = session.isInitiator() ? feeFromChannelSats * 1000n : 0n;
		const myNewLocalMsat =
			this._state.localBalanceMsat +
			session.getLocalRelativeSatoshis() * 1000n -
			myFeeMsat;
		let htlcInFlightMsat = 0n;
		for (const e of this._state.htlcs.values()) {
			htlcInFlightMsat += e.amountMsat;
		}
		const theirNewMsat =
			newCapacity * 1000n - myNewLocalMsat - htlcInFlightMsat;
		const ourDust = this._state.localConfig.dustLimitSatoshis;
		const peerDust = this._state.remoteConfig.dustLimitSatoshis;
		if (theyAdded) {
			const theirReserve = v2ReserveWeEnforce(newCapacity, ourDust, peerDust);
			if (theirNewMsat < theirReserve * 1000n) {
				return `splice leaves the peer balance ${
					theirNewMsat / 1000n
				} sats below the channel reserve ${theirReserve} sats at the new capacity ${newCapacity} sats`;
			}
		}
		if (weAdded) {
			const ourReserve = v2ReserveWeKeep(newCapacity, ourDust, peerDust);
			if (myNewLocalMsat < ourReserve * 1000n) {
				return `splice leaves our balance ${
					myNewLocalMsat / 1000n
				} sats below the channel reserve ${ourReserve} sats at the new capacity ${newCapacity} sats`;
			}
		}
		return null;
	}

	private _v2NegotiatedTx(): {
		tx: import('bitcoinjs-lib').Transaction;
		outputIndex: number;
	} | null {
		const session = this._state.dualFundingSession;
		if (!session || !this._state.remoteBasepoints) return null;
		const built = session.buildTransaction();
		if (!built) return null;
		let tx;
		try {
			// The interactive-tx final ordering (ascending serial_id) is exactly
			// what buildSpliceTx produces; both sides derive the identical txid.
			tx = buildSpliceTx(
				built.inputs.map((i: IInteractiveTxInput) => ({
					serialId: i.serialId,
					prevTxid:
						i.prevTx && i.prevTx.length >= 32
							? extractTxidFromPrevTx(i.prevTx)
							: i.prevTxid,
					prevOutputIndex: i.prevTxVout ?? i.prevOutputIndex,
					sequence: i.sequence
				})),
				built.outputs.map((o: IInteractiveTxOutput) => ({
					serialId: o.serialId,
					script: o.scriptPubkey,
					valueSats: o.amountSats
				})),
				built.locktime
			);
		} catch {
			return null;
		}
		const funding = createFundingScript(
			this._state.localBasepoints.fundingPubkey,
			this._state.remoteBasepoints.fundingPubkey
		);
		const outputIndex = findOutputIndex(tx, funding.p2wshOutput);
		if (outputIndex < 0) return null;
		if (BigInt(tx.outs[outputIndex].value) !== this._state.fundingSatoshis) {
			return null;
		}
		return { tx, outputIndex };
	}

	private _v2FundingOutpoint(): { txid: Buffer; outputIndex: number } | null {
		// The record (created at the commitment point from the live builder) is
		// authoritative once it exists, and the only source after a restart.
		// A RETAINED rollback record describes the REPLACED attempt: fall
		// through to the live builder so nothing of the new round ever binds
		// to the old outpoint.
		const record = this._state.v2InFlight;
		if (record && !this._v2RecordIsStaleRollback()) {
			return {
				txid: Buffer.from(record.fundingTxid),
				outputIndex: record.fundingOutputIndex
			};
		}
		const built = this._v2NegotiatedTx();
		if (!built) return null;
		return {
			txid: Buffer.from(built.tx.getHash()),
			outputIndex: built.outputIndex
		};
	}

	/**
	 * Compute the tx-input indices we own (BOLT 2: initiator uses even serial
	 * ids, the acceptor odd) and, when the wallet contribution closures are
	 * live, sign each of our inputs over the negotiated tx (BIP 341: P2TR
	 * closures sign over ALL prevouts; P2WPKH closures ignore the extra
	 * argument). Witnesses are applied to built.tx in place. With no
	 * contribution registered the witness list is empty: either we own no
	 * inputs (a complete answer) or the caller drives sendTxSignatures itself
	 * (the witnesses are recorded when they are released). Returns null when a
	 * prevout cannot be resolved or a contributed input has no closure —
	 * nothing must be signed or recorded in that case.
	 */
	private _signV2ContributionWitnesses(built: {
		tx: import('bitcoinjs-lib').Transaction;
		outputIndex: number;
	}): { witnesses: Buffer[][]; indices: number[] } | null {
		const session = this._state.dualFundingSession;
		const builder = session?.getTxBuilder();
		if (!session || !builder) return null;
		const sorted = [...builder.getInputs()].sort((a, b) =>
			a.serialId < b.serialId ? -1 : 1
		);
		if (sorted.length !== built.tx.ins.length) return null;
		const indices: number[] = [];
		for (let i = 0; i < sorted.length; i++) {
			if ((sorted[i].serialId % 2n === 0n) === session.isInitiator()) {
				indices.push(i);
			}
		}
		const c = this._dualFundingContribution;
		if (!c) return { witnesses: [], indices };
		const prevouts = this._collectPrevouts(built.tx, sorted);
		if (!prevouts) return null;
		const witnesses: Buffer[][] = [];
		for (const i of indices) {
			const prevTxid = Buffer.from(built.tx.ins[i].hash);
			const vout = built.tx.ins[i].index;
			const w = c.inputs.find(
				(wi) =>
					extractTxidFromPrevTx(wi.prevTx).equals(prevTxid) &&
					wi.prevOutputIndex === vout
			);
			if (!w) return null;
			const witness = w.signWitness(built.tx, i, w.value, prevouts);
			built.tx.setWitness(i, witness);
			witnesses.push(witness);
		}
		return { witnesses, indices };
	}

	/**
	 * Create or patch the durable v2 open record. Created at the point of no
	 * return — our initial commitment_signed is about to leave — from the LIVE
	 * session and interactive-tx builder: the negotiated tx, the tx_signatures
	 * ordering and our wallet witnesses cannot be recomputed after a restart,
	 * so everything resumption needs is captured here, and our inputs are
	 * signed NOW while the wallet closures are live (they still only LEAVE
	 * under the commitment-round and ordering gates of _maybeSendV2TxSigs).
	 * Later calls patch the existing record; restored (builder-less) sessions
	 * only ever patch.
	 */
	private _syncV2InFlight(changes: Partial<IV2InFlight>): void {
		// A retained record from a REPLACED attempt (rollback state held
		// through an accepted RBF) must never be patched with the new
		// round's data: the new attempt records itself FRESH here, and the
		// single persist that carries it is the durable boundary where the
		// previous attempt stops being resumable. Until that write lands,
		// every rollback arm still finds the old record and returns both
		// sides to it, so a failed persist cannot leave the two peers
		// holding different attempts.
		if (!this._state.v2InFlight || this._v2RecordIsStaleRollback()) {
			// Build the ENTIRE replacement first: every fallible step
			// (negotiated-tx assembly, wallet witness signing, prevout
			// capture) must succeed before anything is swapped, so a failure
			// mid-construction can never leave memory recordless while the
			// disk still holds the retained previous attempt.
			const candidate = this._buildV2InFlightRecord();
			if (!candidate) return;
			// A replaced attempt whose signatures were exchanged stays
			// broadcastable: the replacement double-spends it, but a miner may
			// still pick it, so it must remain tracked (and chain-watched)
			// until one attempt confirms. Pre-signature replacements carry no
			// broadcast risk and are dropped as before.
			const outgoing = this._state.v2InFlight;
			if (outgoing && this._v2RecordBroadcastable(outgoing)) {
				this._state.v2PreviousAttempts = [
					...(this._state.v2PreviousAttempts ?? []),
					outgoing
				];
			}
			this._state.v2InFlight = candidate;
		}
		Object.assign(this._state.v2InFlight, changes);
	}

	/**
	 * Whether the current record is RETAINED rollback state from a replaced
	 * attempt: an accepted RBF bumps the session's attempt counter
	 * immediately, while the record keeps describing the previous attempt
	 * until the new one replaces it at its commitment persist.
	 */
	private _v2RecordIsStaleRollback(): boolean {
		return !!(
			this._state.v2InFlight &&
			this._state.dualFundingSession &&
			this._state.v2InFlight.rbfAttempt !==
				this._state.dualFundingSession.getRbfCount()
		);
	}

	/**
	 * Assemble the complete in-flight record for the CURRENT attempt from
	 * the live session and builder, or null when any step fails. Pure
	 * construction: nothing on the channel is mutated.
	 */
	private _buildV2InFlightRecord(): IV2InFlight | null {
		const session = this._state.dualFundingSession;
		if (!session) return null;
		const built = this._v2NegotiatedTx();
		if (!built) return null;
		const signed = this._signV2ContributionWitnesses(built);
		if (!signed) return null;
		// The complete prevout set must survive the process: witness
		// validation after a restart has nothing else to bind and verify
		// the peer's signatures against.
		const prevouts = this._v2InputPrevouts();
		if (!prevouts) return null;
		const params = session.getLocalParams();
		return {
			fundingTxid: Buffer.from(built.tx.getHash()),
			fundingOutputIndex: built.outputIndex,
			// The signing pass above applied our witnesses to built.tx.
			fundingTxHex: built.tx.toHex(),
			fullySigned: false,
			isInitiator: session.isInitiator(),
			localContributionSats: params?.fundingSatoshis ?? 0n,
			remoteContributionSats: session.getRemoteFundingSatoshis(),
			fundingFeeratePerkw:
				params?.fundingFeeratePerkw ??
				session.getOpenMsg()?.fundingFeeratePerkw ??
				0,
			weSignFirst: this._v2ShouldSignFirst(),
			ourWitnesses: signed.witnesses,
			ourWalletInputIndices: signed.indices,
			inputPrevouts: prevouts.scripts.map((s, i) => ({
				script: Buffer.from(s),
				valueSats: prevouts.values[i]
			})),
			remoteCommitmentSig: null,
			sentTxSignatures: false,
			receivedTxSignatures: false,
			confirmed: false,
			rbfAttempt: session.getRbfCount(),
			// The values this attempt's commitment #0 is about to be built at.
			// Any contribution change was already applied to live state when
			// the renegotiation was accepted, so these are this attempt's own.
			fundingSatoshis: this._state.fundingSatoshis,
			localBalanceMsat: this._state.localBalanceMsat,
			remoteBalanceMsat: this._state.remoteBalanceMsat,
			remoteChannelReserveSatoshis:
				this._state.remoteConfig.channelReserveSatoshis,
			localChannelReserveSatoshis:
				this._state.localConfig.channelReserveSatoshis
		};
	}

	/**
	 * The v2 signature exchange just completed: record the fully-signed
	 * funding tx for EVERY role — a restart (or a guardian restore) must be
	 * able to rebroadcast it, and the record answers a peer that still asks
	 * for our tx_signatures over reestablish. The staged pendingFundingTxHex
	 * rides the existing startup-rebroadcast and per-block retry machinery.
	 * Returns false when the complete transaction cannot be assembled, in
	 * which case NOTHING is recorded: marking the peer's witnesses received
	 * without their bytes would lose the only copy of them on restart and
	 * silence the next_funding announcement that lets the peer resend them.
	 */
	private _recordV2FullySigned(): boolean {
		const assembled = this._assembleV2FundingTx();
		if (!assembled) return false;
		this._state.pendingFundingTxHex = assembled.toString('hex');
		this._syncV2InFlight({
			receivedTxSignatures: true,
			fullySigned: true,
			fundingTxHex: assembled.toString('hex')
		});
		return true;
	}

	/**
	 * The complete prevout set of the negotiated funding tx (script and value
	 * per input, in tx-input order): from the live builder's prev_txs while
	 * it exists, from the durable record after a restart (captured at record
	 * creation, when the prev_txs were last in hand). Null when unresolvable,
	 * in which case nothing about the peer's witnesses can be judged and the
	 * exchange must not advance.
	 */
	private _v2InputPrevouts(): { scripts: Buffer[]; values: bigint[] } | null {
		const session = this._state.dualFundingSession;
		const builder = session?.getTxBuilder();
		if (session && builder) {
			const built = this._v2NegotiatedTx();
			if (!built) return null;
			const sorted = [...builder.getInputs()].sort((a, b) =>
				a.serialId < b.serialId ? -1 : 1
			);
			if (sorted.length !== built.tx.ins.length) return null;
			return this._collectPrevouts(built.tx, sorted);
		}
		const record = this._state.v2InFlight;
		if (!record || record.inputPrevouts.length === 0) return null;
		return {
			scripts: record.inputPrevouts.map((p) => p.script),
			values: record.inputPrevouts.map((p) => p.valueSats)
		};
	}

	/**
	 * BOLT 2 receive-side checks specific to an RBF attempt, run beside the
	 * general negotiated-tx audit when previous broadcastable attempts exist:
	 * the replacement MUST share at least one input with EACH previous
	 * funding tx (otherwise two attempts could both confirm), and its total
	 * fees MUST NOT be less than the last successfully negotiated attempt's.
	 * Shared-deterministic: both peers run it over the same tx, so a refusal
	 * is safe to roll back. The fee comparison is skipped when either side's
	 * fee cannot be computed (unparseable prev_tx), mirroring the general
	 * audit's strictness rules; the double-spend check never is.
	 */
	private _v2RbfAttemptAuditError(): string | null {
		const previous = [...(this._state.v2PreviousAttempts ?? [])];
		const retained = this._state.v2InFlight;
		if (
			retained &&
			this._v2RecordIsStaleRollback() &&
			this._v2RecordBroadcastable(retained)
		) {
			previous.push(retained);
		}
		if (previous.length === 0) return null;
		const built = this._v2NegotiatedTx();
		if (!built) {
			return 'replacement funding tx cannot be assembled for the RBF audit';
		}
		const newOutpoints = new Set(
			built.tx.ins.map((i) => `${i.hash.toString('hex')}:${i.index}`)
		);
		for (const rec of previous) {
			let prevAttemptTx: bitcoin.Transaction;
			try {
				prevAttemptTx = bitcoin.Transaction.fromHex(rec.fundingTxHex);
			} catch {
				return `funding attempt ${rec.rbfAttempt} is unreadable for the RBF audit`;
			}
			const shared = prevAttemptTx.ins.some((i) =>
				newOutpoints.has(`${i.hash.toString('hex')}:${i.index}`)
			);
			if (!shared) {
				return `replacement does not double-spend funding attempt ${rec.rbfAttempt}`;
			}
		}
		// Fee floor vs the LAST successfully negotiated attempt (newest last;
		// the retained record, when present, is newer than every entry of
		// v2PreviousAttempts by construction).
		const last = previous[previous.length - 1];
		const prevouts = this._v2InputPrevouts();
		if (!prevouts || last.inputPrevouts.length === 0) return null;
		let lastTx: bitcoin.Transaction;
		try {
			lastTx = bitcoin.Transaction.fromHex(last.fundingTxHex);
		} catch {
			return null;
		}
		if (last.inputPrevouts.length !== lastTx.ins.length) return null;
		const sum = (values: bigint[]): bigint =>
			values.reduce((a, b) => a + b, 0n);
		const lastFee =
			sum(last.inputPrevouts.map((p) => p.valueSats)) -
			sum(lastTx.outs.map((o) => BigInt(o.value)));
		const newFee =
			sum(prevouts.values) - sum(built.tx.outs.map((o) => BigInt(o.value)));
		if (newFee < lastFee) {
			return `replacement fee ${newFee} is below the previous attempt's fee ${lastFee}`;
		}
		return null;
	}

	/**
	 * The complete prevout set of the negotiated splice tx (script and value
	 * per input, in tx-input order, the shared funding input included): from
	 * the live builder's prev_txs while it exists, from the durable record
	 * after a restart (captured at record creation, when the prev_txs were
	 * last in hand). Null when neither source resolves; a record persisted
	 * before prevouts were captured resolves nothing.
	 */
	private _spliceInputPrevouts(): {
		scripts: Buffer[];
		values: bigint[];
	} | null {
		const builder = this._spliceSession?.getTxBuilder();
		const st = this._spliceTx;
		if (builder && st) {
			const sorted = [...builder.getInputs()].sort((a, b) =>
				a.serialId < b.serialId ? -1 : 1
			);
			if (sorted.length !== st.tx.ins.length) return null;
			const p2wshScript = bitcoin.payments.p2wsh({
				redeem: { output: st.oldWitnessScript }
			}).output as Buffer;
			return this._collectPrevouts(st.tx, sorted, {
				index: st.sharedInputIndex,
				script: p2wshScript,
				value: this._state.fundingSatoshis
			});
		}
		const record = this._state.spliceInFlight;
		if (!record?.inputPrevouts || record.inputPrevouts.length === 0) {
			return null;
		}
		return {
			scripts: record.inputPrevouts.map((p) => p.script),
			values: record.inputPrevouts.map((p) => p.valueSats)
		};
	}

	/** The tx-input indices of the PEER's funding inputs, ascending. */
	private _v2PeerInputIndices(inputCount: number): number[] | null {
		const session = this._state.dualFundingSession;
		const builder = session?.getTxBuilder();
		if (session && builder) {
			const sorted = [...builder.getInputs()].sort((a, b) =>
				a.serialId < b.serialId ? -1 : 1
			);
			if (sorted.length !== inputCount) return null;
			const indices: number[] = [];
			for (let i = 0; i < sorted.length; i++) {
				if ((sorted[i].serialId % 2n === 0n) !== session.isInitiator()) {
					indices.push(i);
				}
			}
			return indices;
		}
		const record = this._state.v2InFlight;
		if (!record) return null;
		const ours = new Set(record.ourWalletInputIndices);
		const indices: number[] = [];
		for (let i = 0; i < inputCount; i++) {
			if (!ours.has(i)) indices.push(i);
		}
		return indices;
	}

	/**
	 * Validate the peer's tx_signatures witnesses BEFORE they enter the
	 * session: exactly one stack per peer input, each bound to its negotiated
	 * prevout and cryptographically verified. P2WPKH: [DER SIGHASH_ALL
	 * signature, pubkey], the pubkey must hash to the program and the
	 * signature must verify over the BIP 143 sighash. P2TR key-spend: a
	 * 64-byte (SIGHASH_DEFAULT) or 65-byte explicit-ALL schnorr signature,
	 * verified over the matching BIP 341 sighash against the output key.
	 * P2WSH and taproot script-path witnesses cannot be judged generically
	 * (the script's semantics are its own) and fail closed. Returns the
	 * problem, or null when acceptable.
	 */
	private _validateV2PeerWitnesses(witnesses: Buffer[][]): string | null {
		const prevouts = this._v2InputPrevouts();
		if (!prevouts) return 'funding prevouts cannot be resolved';
		const record = this._state.v2InFlight;
		let tx: import('bitcoinjs-lib').Transaction;
		const built = this._v2NegotiatedTx();
		if (built) {
			tx = built.tx;
		} else if (record) {
			try {
				tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
			} catch {
				return 'negotiated funding tx cannot be resolved';
			}
		} else {
			return 'negotiated funding tx cannot be resolved';
		}
		if (prevouts.scripts.length !== tx.ins.length) {
			return 'funding prevouts do not cover the negotiated tx';
		}
		const peerIndices = this._v2PeerInputIndices(tx.ins.length);
		if (!peerIndices) return 'peer funding inputs cannot be resolved';
		if (witnesses.length !== peerIndices.length) {
			return `expected ${peerIndices.length} witness stacks, got ${witnesses.length}`;
		}
		for (let k = 0; k < peerIndices.length; k++) {
			const problem = this._validateWitnessForInput(
				tx,
				peerIndices[k],
				witnesses[k],
				prevouts
			);
			if (problem) return problem;
		}
		return null;
	}

	/**
	 * Record, durably and with its OWN script, the funding outpoint this splice
	 * is about to supersede (issue #479).
	 *
	 * Called where the splice's WATCH_FUNDING is pushed, which is where the
	 * channel's own funding watch MOVES to the new outpoint and the old one
	 * stops being covered. Two things make that the right moment and this the
	 * right layer:
	 *
	 * - It runs while the action array is still being BUILT, so completeSplice
	 *   has not adopted the new funding yet and `fundingTxid`, the output
	 *   index and `remoteBasepoints.fundingPubkey` are all still the
	 *   pre-splice ones. On a zero-conf channel splice_locked leaves in this
	 *   same batch, so anything reading channel state afterwards, including
	 *   the node's own watch:funding handler, may already see the post-splice
	 *   values.
	 * - The batch's PERSIST_STATE therefore carries this record, which puts it
	 *   on disk before the transaction that supersedes the outpoint is
	 *   authorized to reach the network. A crash in between leaves the record,
	 *   not a gap.
	 *
	 * The script is stored rather than recomputed because a splice may rotate
	 * the peer's funding pubkey, so the channel's later funding script can
	 * hash to something this output never paid.
	 *
	 * RETURNS the action that arms the watch, rather than leaving arming to
	 * whatever the caller remembers to push next to it. Three of the four call
	 * sites got arming for free from a WATCH_FUNDING they happened to emit
	 * anyway; the fourth is the EARLIEST point of no return, it emits no
	 * WATCH_FUNDING because the splice transaction has not been broadcast, and
	 * it therefore left the superseded outpoint with no live subscription at
	 * all between our signature leaving and the peer's arriving.
	 */
	private _recordPreSpliceSpendWatch(spliceTxid: Buffer): ChannelAction[] {
		const fundingTxid = this._state.fundingTxid;
		if (!fundingTxid || !this._state.remoteBasepoints) return [];
		const txid = Buffer.from(fundingTxid).reverse().toString('hex');
		const outputIndex = this._state.fundingOutputIndex;
		const existing = this._state.preSpliceSpendWatches ?? [];
		if (
			existing.some((w) => w.txid === txid && w.outputIndex === outputIndex)
		) {
			// Already recorded, but still arm: arming is idempotent per
			// outpoint, and a refusal path re-entered after a reconnect has to
			// be able to put the watch back.
			return this._armPreSpliceSpendWatches();
		}
		const script = isTaprootChannel(this._state.channelType)
			? createTaprootFundingScript(
					this._state.localBasepoints.fundingPubkey,
					this._state.remoteBasepoints.fundingPubkey
			  ).p2trOutput
			: createFundingScript(
					this._state.localBasepoints.fundingPubkey,
					this._state.remoteBasepoints.fundingPubkey
			  ).p2wshOutput;
		this._state.preSpliceSpendWatches = [
			...existing,
			{
				txid,
				outputIndex,
				script: script.toString('hex'),
				spliceTxid: Buffer.from(spliceTxid).reverse().toString('hex')
			}
		];
		return this._armPreSpliceSpendWatches();
	}

	/** The action that arms every pre-splice leg this channel has recorded. */
	private _armPreSpliceSpendWatches(): ChannelAction[] {
		const channelId = this._state.channelId;
		if (!channelId) return [];
		return [{ type: ChannelActionType.WATCH_PRESPLICE_SPEND, channelId }];
	}

	/**
	 * Record the still-current funding outpoint as the pre-splice spend watch
	 * for the splice in flight, for a row written before `preSpliceSpendWatches`
	 * existed that was mid-splice when the node upgraded (issue #479). Returns
	 * whether the list changed, so the caller knows to persist.
	 *
	 * Legal ONLY while `spliceInFlight` is set, and that is exactly what makes
	 * the derivation sound rather than a guess: completeSplice has not adopted
	 * the new funding, so `fundingTxid` is still the outpoint the splice will
	 * supersede and `remoteBasepoints.fundingPubkey` is still the PRE-splice
	 * key. The same derivation is wrong the moment the splice locks, because a
	 * splice may rotate that key and completeSplice adopts the rotation.
	 *
	 * And ONLY past the point of no return. Before our tx_signatures leave,
	 * nobody can broadcast that splice, so the outpoint needs no leg - while
	 * recording one anyway makes it OUTLIVE the negotiation: such a splice can
	 * still be safely aborted, and the record would then name a transaction
	 * that will never exist. Legs are keyed per outpoint, so that stale entry
	 * also blocks a later splice of the SAME outpoint from recording its real
	 * expected spender, and the watcher would report that splice's own valid
	 * transaction as a close.
	 *
	 * The channel derives it rather than the node, so the taproot branch, the
	 * display-order conversion and the per-outpoint dedupe all live in one
	 * place: the private writer this delegates to.
	 */
	recordInFlightPreSpliceSpendWatch(): boolean {
		const record = this._state.spliceInFlight;
		if (!record) return false;
		if (record.sentTxSignatures !== true) return false;
		const before = this._state.preSpliceSpendWatches?.length ?? 0;
		this._recordPreSpliceSpendWatch(record.spliceTxid);
		return (this._state.preSpliceSpendWatches?.length ?? 0) !== before;
	}

	/**
	 * Build the non-terminal refusal batch for an unacceptable splice
	 * tx_signatures: used by the wallet-witness arm, the after-sent txid
	 * mismatch, and the defensive apply-failure arm, where the peer may still
	 * retransmit an honest message (e.g. on reconnect) and the exchange can
	 * complete. Refusing the message does not make the splice unconfirmable
	 * once OUR shared-input signature has left: witness data does not change
	 * the txid (BIP 141), so the peer can broadcast its locally valid copy of
	 * the same transaction. Keep watching the negotiated outpoint so a
	 * confirmation still locks the splice.
	 */
	private _spliceTxSigsRefusal(message: string): ChannelAction[] {
		const refusal: ChannelAction[] = [];
		const record = this._state.spliceInFlight;
		if (record && (this._spliceSentTxSigs || record.sentTxSignatures)) {
			// The leg it records has to reach disk: this batch is the only
			// thing that knows about it, and nothing downstream of a refusal is
			// guaranteed to persist.
			refusal.push({ type: ChannelActionType.PERSIST_STATE });
			refusal.push(...this._recordPreSpliceSpendWatch(record.spliceTxid));
			refusal.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: record.spliceTxid,
				fundingOutputIndex: record.newFundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});
		}
		refusal.push({ type: ChannelActionType.ERROR, message });
		return refusal;
	}

	/**
	 * Terminal failure for a splice tx_signatures whose shared-input signature
	 * is missing or invalid: BOLT 2 requires sending an error and failing the
	 * channel. The splice record and session are deliberately retained (the
	 * wire-failure helper touches neither): while our own signature has left,
	 * the peer holds a broadcastable copy, so the outpoint stays watched and a
	 * confirmation is adopted by the force-close planner's splice adoption;
	 * restore re-arms both across restarts.
	 */
	private _spliceTxSigsWireFailure(message: string): ChannelAction[] {
		const actions: ChannelAction[] = [];
		const record = this._state.spliceInFlight;
		if (record && (this._spliceSentTxSigs || record.sentTxSignatures)) {
			actions.push(...this._recordPreSpliceSpendWatch(record.spliceTxid));
			actions.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: record.spliceTxid,
				fundingOutputIndex: record.newFundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});
		}
		actions.push(...this._failChannelWithWireError(message));
		return actions;
	}

	/**
	 * Validate the peer's splice tx_signatures wallet witnesses BEFORE they
	 * are applied and the splice tx broadcast: exactly one stack per peer
	 * wallet input, each bound to its negotiated prevout and
	 * cryptographically verified (the same rules as _validateV2PeerWitnesses).
	 * The count check always runs; the per-witness cryptographic checks are
	 * skipped only for a restored builder-less session whose record predates
	 * prevout capture, where refusing would wedge a live channel's in-flight
	 * splice (the shared-input 2-of-2 verification still gates the exchange).
	 * Returns the problem, or null when acceptable.
	 */
	private _validateSplicePeerWitnesses(witnesses: Buffer[][]): string | null {
		const st = this._spliceTx;
		if (!st) return 'no negotiated splice transaction';
		const ours = new Set(st.ourWalletInputIndices);
		const peerIndices: number[] = [];
		for (let i = 0; i < st.tx.ins.length; i++) {
			if (i === st.sharedInputIndex || ours.has(i)) continue;
			peerIndices.push(i);
		}
		if (witnesses.length !== peerIndices.length) {
			return `expected ${peerIndices.length} witness stacks, got ${witnesses.length}`;
		}
		if (peerIndices.length === 0) return null;
		const prevouts = this._spliceInputPrevouts();
		if (!prevouts) {
			if (!this._spliceSession?.getTxBuilder()) return null;
			return 'splice funding prevouts cannot be resolved';
		}
		if (prevouts.scripts.length !== st.tx.ins.length) {
			return 'splice prevouts do not cover the negotiated tx';
		}
		for (let k = 0; k < peerIndices.length; k++) {
			const problem = this._validateWitnessForInput(
				st.tx,
				peerIndices[k],
				witnesses[k],
				prevouts
			);
			if (problem) return problem;
		}
		return null;
	}

	/**
	 * Interactive-tx funding inputs we will have to judge witnesses for (v2
	 * open inputs, splice remote inputs) must pay P2WPKH or P2TR: those are
	 * the only prevout types whose tx_signatures witnesses can be
	 * cryptographically verified, and an unverifiable input must never make
	 * it into the negotiated tx.
	 */
	private _v2CheckInputSpendable(input: IInteractiveTxInput): string | null {
		if (!input.prevTx || input.prevTx.length < 32) {
			return 'funding input carries no previous transaction';
		}
		let script: Buffer;
		try {
			const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
			const out = prev.outs[input.prevTxVout ?? input.prevOutputIndex];
			if (!out) return 'funding input names a missing prevout';
			script = Buffer.from(out.script);
		} catch {
			return 'funding input previous transaction is unreadable';
		}
		const isP2wpkh =
			script.length === 22 && script[0] === 0x00 && script[1] === 0x14;
		const isP2tr =
			script.length === 34 && script[0] === 0x51 && script[1] === 0x20;
		if (!isP2wpkh && !isP2tr) {
			return 'funding input pays an unsupported output type (only P2WPKH and P2TR witnesses can be verified)';
		}
		return null;
	}

	private _validateWitnessForInput(
		tx: import('bitcoinjs-lib').Transaction,
		index: number,
		stack: Buffer[],
		prevouts: { scripts: Buffer[]; values: bigint[] }
	): string | null {
		const script = prevouts.scripts[index];
		const value = prevouts.values[index];
		if (stack.length === 0) return 'empty witness stack';
		// bitcoinjs sighash APIs take number values; above 2^53 the
		// narrowing would silently compute a wrong sighash and fail the
		// verify for the wrong reason. No real prevout gets there (21M BTC
		// in sats fits), so refuse loudly instead of narrowing quietly.
		if (prevouts.values.some((v) => v > BigInt(Number.MAX_SAFE_INTEGER))) {
			return 'prevout value exceeds the safe integer range';
		}
		const isP2wpkh =
			script.length === 22 && script[0] === 0x00 && script[1] === 0x14;
		const isP2wsh =
			script.length === 34 && script[0] === 0x00 && script[1] === 0x20;
		const isP2tr =
			script.length === 34 && script[0] === 0x51 && script[1] === 0x20;
		if (isP2wpkh) {
			if (stack.length !== 2) {
				return 'P2WPKH witness must be [signature, pubkey]';
			}
			const decoded = this._decodeDerSighashAll(stack[0]);
			if (typeof decoded === 'string') return `P2WPKH ${decoded}`;
			const pubkey = stack[1];
			if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) {
				return 'P2WPKH witness pubkey is malformed';
			}
			if (!bitcoin.crypto.hash160(pubkey).equals(script.subarray(2))) {
				return 'P2WPKH witness pubkey does not match the prevout program';
			}
			const scriptCode = bitcoin.payments.p2pkh({
				hash: script.subarray(2)
			}).output!;
			const sighash = tx.hashForWitnessV0(
				index,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			let valid = false;
			try {
				// strict: high-S signatures are refused (BIP 62 standardness).
				valid = ecc.verify(sighash, pubkey, decoded, true);
			} catch {
				// A malformed peer-controlled point must fail the negotiation,
				// not escape the validator as an exception.
				valid = false;
			}
			if (!valid) {
				return 'P2WPKH signature does not verify against its prevout';
			}
			return null;
		}
		if (isP2tr) {
			if (stack.length === 1) {
				const sig = stack[0];
				// BOLT 2 names SIGHASH_ALL for tx_signatures, but BIP 341's
				// 64-byte SIGHASH_DEFAULT shorthand commits to exactly the
				// same transaction data, and common signers (Bitcoin Core,
				// libwally, and so eclair and CLN) emit it for taproot
				// inputs: both forms are accepted. A 65-byte signature with
				// any other trailing byte stays refused, including 0x00,
				// which BIP 341 forbids in the explicit form.
				const isDefaultForm = sig.length === 64;
				if (!isDefaultForm && (sig.length !== 65 || sig[64] !== 0x01)) {
					return 'P2TR key-spend signature must be the 64-byte SIGHASH_DEFAULT form or carry an explicit SIGHASH_ALL byte';
				}
				// The hash type byte is part of the BIP 341 message, so the
				// sighash must be computed for the form the witness carries.
				const sighash = tx.hashForWitnessV1(
					index,
					prevouts.scripts,
					prevouts.values.map((v) => Number(v)),
					isDefaultForm
						? bitcoin.Transaction.SIGHASH_DEFAULT
						: bitcoin.Transaction.SIGHASH_ALL
				);
				let valid = false;
				try {
					valid = ecc.verifySchnorr(
						sighash,
						script.subarray(2),
						sig.subarray(0, 64)
					);
				} catch {
					valid = false;
				}
				if (!valid) {
					return 'P2TR signature does not verify against its prevout';
				}
				return null;
			}
			// Script-path spends cannot be verified generically (the leaf
			// semantics are the script's own): fail closed rather than accept
			// a witness this validator cannot judge. The negotiation-time
			// check keeps P2TR prevouts acceptable, because a KEY-spend of
			// them is fully verifiable; only the path choice is refused here.
			return 'P2TR script-path spends are not supported for funding inputs';
		}
		if (isP2wsh) {
			// A P2WSH witness cannot be verified without executing the script
			// (a hash-matched OP_FALSE spend would pass any structural check):
			// fail closed. The negotiation-time check refuses P2WSH funding
			// inputs before anything signs, so this is defense in depth.
			return 'P2WSH peer funding inputs are not supported (the witness cannot be verified)';
		}
		return 'peer funding input is not a supported segwit output';
	}

	/**
	 * Decode a DER-encoded signature-with-sighash element; returns the raw
	 * 64-byte signature when it is structurally valid AND carries an explicit
	 * SIGHASH_ALL byte, or the problem as a string.
	 */
	private _decodeDerSighashAll(el: Buffer): Buffer | string {
		let decoded: { signature: Buffer; hashType: number };
		try {
			decoded = bitcoin.script.signature.decode(el);
		} catch {
			return 'signature is not a valid DER signature';
		}
		if (decoded.hashType !== bitcoin.Transaction.SIGHASH_ALL) {
			return 'signature is not SIGHASH_ALL';
		}
		return decoded.signature;
	}

	/**
	 * Reset the process-local v2 open driver: an accepted RBF renegotiation,
	 * an abort, or the drop of an unresumable session starts the commitment
	 * and tx_signatures round over (or ends it) with no stale releases.
	 */
	private _resetV2Driver(): void {
		this._v2SentCommitment = false;
		this._v2ReceivedCommitment = false;
		this._v2PendingTxSigs = null;
		this._v2TxSigsReleased = false;
		this._v2CallerTxSigsSignaled = false;
	}

	/**
	 * Send our commitment_signed for the peer's commitment #0 once both sides
	 * have sent tx_complete (BOLT 2 v2 establishment: the commitment_signed
	 * exchange precedes tx_signatures). Idempotent.
	 */
	private _maybeSendV2Commitment(peerCommitted = false): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (
			!session ||
			session.getState() !== DualFundingState.AWAITING_TX_SIGNATURES ||
			this._v2SentCommitment ||
			!this._signer ||
			!this._state.remoteBasepoints ||
			!this._state.remoteCurrentPerCommitmentPoint
		) {
			return [];
		}
		// An un-echoed abort freezes the commitment release too: a signature
		// handed to the peer while we are asking it to forget the attempt
		// extends what it can enforce against an attempt we may then drop at
		// the echo. The freeze thaws with the abort (echo teardown keeps
		// broadcastable attempts; disconnect forgets the abort entirely).
		// The rollback abort freezes it the same way until its echo.
		if (this._v2AbortPending || this._v2RollbackAbortPending) return [];
		// v2 + simple taproot would need a MuSig2 funding co-sign round that
		// does not exist yet — fail closed rather than open without an exit.
		if (isTaprootChannel(this._state.channelType)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Taproot dual-funded (v2) opens are not supported'
				}
			];
		}
		// Install the CURRENT attempt's record BEFORE anything is signed: the
		// commitment must spend the attempt being negotiated, never the
		// retained rollback record's outpoint (during an RBF the record still
		// describes the replaced attempt until this very step swaps it). The
		// construction is all-or-nothing, so a failure leaves the rollback
		// record untouched and the renegotiation unwinds to it on the wire.
		const prior = this._state.v2InFlight;
		const priorFundingTxid = this._state.fundingTxid;
		const priorFundingOutputIndex = this._state.fundingOutputIndex;
		this._syncV2InFlight({});
		const record = this._state.v2InFlight;
		if (!record || this._v2RecordIsStaleRollback()) {
			return this._unwindV2NegotiationOrRollback(
				'failed to assemble the replacement funding record — refusing to sign'
			);
		}
		// signRemoteCommitment reads the funding outpoint from state; set it now,
		// before either side has released any signature. The v2 channel_id is the
		// basepoint-derived id set at accept_channel2 (NOT the funding outpoint) —
		// do not overwrite it here.
		this._state.fundingTxid = Buffer.from(record.fundingTxid);
		this._state.fundingOutputIndex = record.fundingOutputIndex;

		let signature: Buffer;
		let htlcSignatures: Buffer[];
		try {
			({ signature, htlcSignatures } = signRemoteCommitment(
				this._state,
				this._signer,
				this._state.remoteCurrentPerCommitmentPoint,
				0n
			));
		} catch {
			// The signer failed AFTER the record swap: undo it before
			// anything else observes attempt N+1, or this side would keep
			// the replacement while the peer keeps the previous attempt and
			// reestablish splits on different funding txids.
			if (prior && peerCommitted) {
				// The signing attempt was triggered by the PEER's commitment
				// for the replacement, which only leaves behind its persist:
				// the peer has durably replaced its rollback record and can
				// NEVER return to the previous attempt. Restoring it here
				// would strand this side on an attempt the peer already
				// abandoned, split until some disconnect. Terminal instead:
				// the abort tears the peer's replacement down, the echo's
				// handshake cleanup removes this side, and both managers and
				// rows converge on the live connection.
				this._state.v2InFlight = null;
				this._state.dualFundingSession?.abort();
				this._state.dualFundingSession = null;
				this._resetV2Driver();
				this._state.state = ChannelState.ERRORED;
				// Condemned IN the terminal persist: the removal is decided
				// here, and a crash before the abort echo (whose handshake
				// cleanup deletes the row) must not restore this as a
				// permanently tracked inert channel. Startup deletes
				// condemned rows instead of restoring them.
				this._state.condemned = true;
				return [
					{ type: ChannelActionType.PERSIST_STATE },
					this._txAbort(
						this._v2ChannelId(),
						'failed to sign the v2 commitment'
					),
					{
						type: ChannelActionType.ERROR,
						message: 'failed to sign the v2 commitment'
					}
				];
			}
			// With the prior record restored, the unwind below rolls back to
			// it on the wire (or aborts a fresh open where there is nothing
			// to keep): the peer has not committed the replacement yet, so
			// the previous attempt is still the shared truth.
			this._state.v2InFlight = prior;
			this._state.fundingTxid = priorFundingTxid;
			this._state.fundingOutputIndex = priorFundingOutputIndex;
			return this._unwindV2NegotiationOrRollback(
				'failed to sign the v2 commitment'
			);
		}
		this._v2SentCommitment = true;
		const msg: ICommitmentSignedMessage = {
			channelId: this._state.channelId!,
			signature,
			htlcSignatures
		};
		// Persist BEFORE the message leaves: the peer holds our signature from
		// this point on.
		const actions: ChannelAction[] = [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.COMMITMENT_SIGNED, encodeCommitmentSignedMessage(msg))
		];
		// A zero-local-input attempt becomes broadcastable the moment this
		// signature leaves (the peer needs no witness bytes from us), so the
		// funding watch arms in the SAME persisted batch: a broadcastable
		// attempt must never exist without a live watch on its outpoint. The
		// per-record test keeps this scoped to THIS attempt: mid-renegotiation
		// the channel-wide answer is true for the retained previous attempts
		// while this record still owes its whole exchange.
		if (this._v2RecordBroadcastable(record)) {
			actions.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: Buffer.from(record.fundingTxid),
				fundingOutputIndex: record.fundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});
		}
		return actions;
	}

	/**
	 * Handle the peer's commitment_signed during a v2 open: ensure ours went
	 * out (the peer may sign first), verify their signature over OUR commitment
	 * #0 — the funding_signed analogue; without it the channel has no
	 * unilateral exit — adopt it, then release tx_signatures per the ordering
	 * rules.
	 */
	private _handleV2CommitmentSigned(
		msg: ICommitmentSignedMessage
	): ChannelAction[] {
		const actions: ChannelAction[] = [];
		// The incoming commitment proves the peer COMMITTED its side (the
		// message only leaves behind the peer's persist); the flag makes a
		// signer failure here terminal rather than a rollback to an attempt
		// the peer can no longer return to.
		actions.push(...this._maybeSendV2Commitment(true));
		if (actions.some((a) => a.type === ChannelActionType.ERROR)) {
			return actions;
		}
		if (this._v2ReceivedCommitment) {
			// Duplicate (retransmit): the first one was verified and adopted.
			return actions;
		}
		// Cannot verify -> must not adopt: an adopted-but-unverified peer
		// commitment would satisfy the tx_signatures release gate below.
		if (!this._signer || !this._state.remoteBasepoints) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Cannot verify commitment signature in v2 open: no signer or remote basepoints'
				}
			];
		}
		const point0 = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			0n
		);
		const valid = verifyRemoteCommitmentSig(
			this._state,
			this._signer,
			point0,
			msg.signature,
			0n
		);
		if (!valid) {
			// Peer-held fault at the signature stage: wire-visible, with the
			// disposition picked by broadcastability (issue 426). The bare
			// ERROR this replaces left a promoted registration behind as a
			// non-ERRORED zombie the peer was never told about.
			return this._failV2SignatureStage(
				'Invalid commitment signature in v2 open'
			);
		}
		this._state.remoteCommitmentSignature = Buffer.from(msg.signature);
		this._state.remoteHtlcSignatures = [];
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);
		this._state.lastSignedCommitLeaseBlockheight =
			getLocalCommitmentLeaseBlockheight(this._state);
		this._v2ReceivedCommitment = true;
		this._syncV2InFlight({ remoteCommitmentSig: Buffer.from(msg.signature) });
		actions.push({ type: ChannelActionType.PERSIST_STATE });
		// Commitment round complete — release tx_signatures if ordering allows.
		actions.push(...this._maybeSendV2TxSigs());
		return actions;
	}

	/**
	 * BOLT 2 interactive-tx ordering: the peer whose inputs contribute less
	 * total value sends tx_signatures first; on an exact tie the lower node_id
	 * signs first (S-2.M5). The node-id ordering is provided by the
	 * ChannelManager; if it is somehow unknown, fall back to the
	 * non-initiator (deterministic and symmetric between beignet peers).
	 */
	private _v2ShouldSignFirst(): boolean {
		const session = this._state.dualFundingSession;
		if (!session) return false;
		// Captured from the live builder at record creation; the only source
		// after a restart, and stable for the whole attempt either way. A
		// RETAINED rollback record describes the REPLACED attempt: fall
		// through to the live builder for the one being negotiated.
		const record = this._state.v2InFlight;
		if (record && !this._v2RecordIsStaleRollback()) return record.weSignFirst;
		const builder = session.getTxBuilder();
		if (!builder) return !session.isInitiator();
		let ours = 0n;
		let theirs = 0n;
		for (const input of builder.getInputs()) {
			// Even serial ids belong to the initiator.
			const isOurs = (input.serialId % 2n === 0n) === session.isInitiator();
			const value = interactiveInputValueSats(input);
			if (value === null) {
				// Unknown input value — cannot apply the spec rule.
				return !session.isInitiator();
			}
			if (isOurs) ours += value;
			else theirs += value;
		}
		if (ours !== theirs) return ours < theirs;
		return this._localNodeIdLower ?? !session.isInitiator();
	}

	/**
	 * Release our tx_signatures once (a) the commitment_signed round finished
	 * with a VERIFIED peer signature over our commitment #0 — the hard
	 * fund-safety gate; releasing witnesses lets the peer broadcast the funding
	 * tx — and (b) the interactive-tx ordering allows it (we sign first, or
	 * the peer's tx_signatures already arrived). Idempotent; defers otherwise.
	 */
	private _maybeSendV2TxSigs(): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session) return [];
		// An un-acked tx_init_rbf freezes this attempt's release: the peer
		// may already have accepted the replacement, in which case witnesses
		// released now belong to an attempt only WE would still track, and
		// the ack would then clear our only record of it. The release
		// resumes when the request is refused (the refusal branch re-drives
		// this) or the request dies with the connection. An un-echoed abort
		// freezes it the same way: witnesses crossing our own abort would
		// hand the peer a broadcastable tx for an attempt we are asking it
		// to forget.
		if (
			this._pendingRbfInit ||
			this._v2AbortPending ||
			this._v2RollbackAbortPending
		) {
			return [];
		}
		if (
			session.getState() !== DualFundingState.AWAITING_TX_SIGNATURES &&
			session.getState() !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return [];
		}
		if (!this._v2SentCommitment || !this._v2ReceivedCommitment) return [];
		// Witnesses go out exactly once; later flushes (e.g. the peer's own
		// tx_signatures arriving after ours) must not re-provide.
		if (this._v2TxSigsReleased) return [];
		const peerSigned = session.getRemoteWitnesses() !== null;
		if (!peerSigned && !this._v2ShouldSignFirst()) return [];

		if (!this._v2PendingTxSigs) {
			const record = this._state.v2InFlight;
			if (
				record &&
				record.ourWitnesses.length === record.ourWalletInputIndices.length
			) {
				// The record was created at the commitment point with our inputs
				// already signed (or with none to sign): release those witnesses
				// verbatim.
				this._v2PendingTxSigs = {
					txid: Buffer.from(record.fundingTxid),
					outputIndex: record.fundingOutputIndex,
					witnesses: record.ourWitnesses.map((w) =>
						w.map((b) => Buffer.from(b))
					)
				};
			} else if (record) {
				// Empty witnesses beside non-empty indices: the caller-driven
				// flow still owes them via sendTxSignatures. Every other release
				// gate has passed, so the send is due NOW and only the caller
				// can supply the bytes. Surface the obligation once per
				// connection cycle instead of waiting silently: after a restart
				// the pending witnesses died with the process and nothing else
				// tells the embedder to re-drive (issue 307).
				if (this._v2CallerTxSigsSignaled) return [];
				this._v2CallerTxSigsSignaled = true;
				return [
					{
						type: ChannelActionType.TX_SIGNATURES_NEEDED,
						channelId: this._v2ChannelId(),
						fundingTxid: Buffer.from(record.fundingTxid),
						fundingOutputIndex: record.fundingOutputIndex,
						inputIndices: [...record.ourWalletInputIndices]
					}
				];
			} else if (this._dualFundingContribution) {
				// No record yet (legacy path): sign our wallet inputs over the
				// negotiated tx via their closures, exactly like splice-in.
				const built = this._v2NegotiatedTx();
				if (!built) return [];
				const signed = this._signV2ContributionWitnesses(built);
				if (!signed) return [];
				this._v2PendingTxSigs = {
					txid: Buffer.from(built.tx.getHash()),
					outputIndex: built.outputIndex,
					witnesses: signed.witnesses
				};
			}
		}

		// A side that contributed no inputs has nothing to sign: auto-fill an
		// empty witness set so a zero-contribution acceptor needs no wallet.
		if (!this._v2PendingTxSigs) {
			const builder = session.getTxBuilder();
			const ownsInput = builder
				?.getInputs()
				.some((i) => (i.serialId % 2n === 0n) === session.isInitiator());
			if (ownsInput !== false) return [];
			const fo = this._v2FundingOutpoint();
			if (!fo) return [];
			this._v2PendingTxSigs = {
				txid: fo.txid,
				outputIndex: fo.outputIndex,
				witnesses: []
			};
		}

		const { txid, outputIndex, witnesses } = this._v2PendingTxSigs;
		const result = session.provideWitnesses(txid, outputIndex, witnesses);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to provide witnesses'
				}
			];
		}
		this._v2PendingTxSigs = null;
		this._v2TxSigsReleased = true;
		// Record the release, and the witnesses that actually left (the
		// caller-driven flow only provides them now).
		this._syncV2InFlight({
			sentTxSignatures: true,
			ourWitnesses: witnesses.map((w) => w.map((b) => Buffer.from(b)))
		});

		// Funding info was already set when the commitment round started; keep
		// the assignment idempotent for callers that reached here another way.
		// The v2 channel_id is the basepoint-derived id (set at accept_channel2),
		// not the funding outpoint — leave it untouched.
		this._state.fundingTxid = Buffer.from(txid);
		this._state.fundingOutputIndex = outputIndex;

		if (session.getState() === DualFundingState.AWAITING_CHANNEL_READY) {
			// The peer's witnesses arrived before ours went out (we sign
			// second, or the caller drove the release): the exchange completes
			// HERE. Never release witnesses into an exchange that cannot be
			// recorded: on an assembly failure roll the release back (nothing
			// has left the wire yet) and fail the negotiation.
			if (!this._recordV2FullySigned()) {
				this._v2TxSigsReleased = false;
				this._syncV2InFlight({ sentTxSignatures: false });
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'v2 funding transaction could not be assembled from the exchanged signatures'
					}
				];
			}
			this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		}

		const msg: ITxSignaturesMessage = {
			channelId: this._v2ChannelId(),
			txid,
			witnesses
		};

		const actions: ChannelAction[] = [
			// Point of no return — the peer can broadcast once this leaves.
			// Persist BEFORE sending.
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.TX_SIGNATURES, encodeTxSignaturesMessage(msg)),
			{
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: txid,
				fundingOutputIndex: outputIndex,
				minimumDepth: this._state.minimumDepth
			}
		];

		// Zero-conf v2: send channel_ready right behind tx_signatures instead of
		// waiting for confirmation, mirroring the v1 fast-tracks on
		// funding_signed. Only meaningful once the funding negotiation is done.
		// Also flush a confirmation that arrived while the exchange was still
		// incomplete (the depth callback is one-shot; see fundingConfirmed).
		if (
			this._state.state === ChannelState.AWAITING_FUNDING_CONFIRMED &&
			((this._state.zeroConfEnabled && this._state.trustedPeer) ||
				this._state.v2InFlight?.confirmed === true)
		) {
			// A parked confirmation names its attempt explicitly (candidates
			// may exist); the zero-conf fast-track has none to name.
			actions.push(
				...this.fundingConfirmed(
					this._state.v2InFlight?.confirmed
						? Buffer.from(this._state.v2InFlight.fundingTxid)
						: undefined
				)
			);
		}

		return actions;
	}

	/**
	 * Provide our tx_signatures for the funding transaction. The witnesses are
	 * released only after the commitment_signed exchange completes and the
	 * interactive-tx ordering allows — until then they are held pending and
	 * flushed automatically (empty action list means deferred, not failed).
	 */
	sendTxSignatures(
		txid: Buffer,
		outputIndex: number,
		witnesses: Buffer[][]
	): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}
		// The caller-driven release honors the same freezes as the automatic
		// one: witnesses crossing our own un-echoed abort (operator or
		// rollback), or an un-acked tx_init_rbf, hand the peer a
		// broadcastable tx for an attempt we are asking it to drop.
		if (
			this._v2AbortPending ||
			this._pendingRbfInit ||
			this._v2RollbackAbortPending
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'tx_signatures release is frozen while an abort or RBF request is pending'
				}
			];
		}

		if (
			session.getState() !== DualFundingState.AWAITING_TX_SIGNATURES &&
			session.getState() !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot send tx_signatures: wrong state'
				}
			];
		}

		// The caller's txid must match the tx both sides actually negotiated —
		// witnesses signed over anything else must never leave.
		const fo = this._v2FundingOutpoint();
		if (!fo || !fo.txid.equals(txid) || fo.outputIndex !== outputIndex) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'tx_signatures txid/output does not match the negotiated funding tx'
				}
			];
		}

		this._v2PendingTxSigs = {
			txid: Buffer.from(txid),
			outputIndex,
			witnesses
		};
		return this._maybeSendV2TxSigs();
	}

	/**
	 * Handle tx_signatures from peer.
	 */
	handleTxSignatures(msg: ITxSignaturesMessage): ChannelAction[] {
		// Splice: the peer's tx_signatures carries its shared-input signature.
		// Verify+assemble the 2-of-2 witness, then broadcast and watch the splice
		// tx for confirmation so we can send splice_locked.
		if (this._spliceSession && !this._spliceSession.isComplete()) {
			// Duplicate tx_signatures (e.g. retransmitted after a reconnect) when we
			// are already fully signed: benign no-op.
			if (this._state.spliceInFlight?.receivedTxSignatures) {
				return [];
			}

			// The peer's 2-of-2 funding signature arrives in the
			// shared_input_signature TLV (BOLT 2 splicing); its witnesses cover
			// only its OWN wallet inputs. Legacy beignet (pre-TLV) sent the sig as
			// witnesses[0] = a single 64-byte element — unambiguous vs real wallet
			// witness stacks (P2WPKH stacks have 2 elements), so accept both.
			let peerSig = msg.sharedInputSignature;
			let peerWalletWitnesses = msg.witnesses || [];
			if (
				!peerSig &&
				peerWalletWitnesses[0]?.length === 1 &&
				peerWalletWitnesses[0][0]?.length === 64
			) {
				peerSig = peerWalletWitnesses[0][0];
				peerWalletWitnesses = peerWalletWitnesses.slice(1);
			}
			if (!peerSig) {
				// BOLT 2 splice tx_signatures: a missing shared_input_signature
				// MUST send an error and fail the channel.
				return this._spliceTxSigsWireFailure(
					'splice tx_signatures missing shared-input signature'
				);
			}

			// All validation runs BEFORE _maybeSendSpliceTxSigs: that helper
			// marks our signatures sent (memory and record) as a side effect,
			// and a refusal must not leave state claiming a send that never
			// happened. The build alone has no such side effects.
			if (!this._spliceTx) {
				this.buildAndSignSpliceTx();
			}

			// BOLT 2: the txid MUST match the negotiated transaction; a
			// mismatch means the peer is signing a different tx and MUST fail
			// the negotiation. Checked first so the diagnosis names the
			// divergence instead of a downstream witness error. A broken
			// restore leaves _spliceTx null; fall through and let the witness
			// validator refuse with its own error.
			if (this._spliceTx) {
				const expectedTxid = Buffer.from(this._spliceTx.tx.getHash());
				if (!msg.txid.equals(expectedTxid)) {
					const reason = `splice tx_signatures txid mismatch: peer=${Buffer.from(
						msg.txid
					)
						.reverse()
						.toString('hex')} ours=${Buffer.from(expectedTxid)
						.reverse()
						.toString('hex')}`;
					if (
						this._spliceSentTxSigs ||
						this._state.spliceInFlight?.sentTxSignatures
					) {
						// Our signatures already left: tx_abort is forbidden and
						// the peer holds a broadcastable copy of the negotiated
						// tx. Non-terminal refusal with the outpoint watched; an
						// honest retransmission (e.g. on reconnect) can recover.
						return this._spliceTxSigsRefusal(reason);
					}
					// Nothing of ours has left: fail the negotiation with
					// tx_abort and unwind, mirroring the tx_complete audit arm.
					// The leading persist makes the abort durable: the in-flight
					// record is already on disk here, and without it a crash
					// would resurrect the aborted splice via
					// restoreSpliceInFlight and the reestablish resume path. No
					// stray-commitment ignore window is armed: the peer's splice
					// commitment_signed always precedes its tx_signatures on the
					// stream and has been consumed by this point.
					return [
						{ type: ChannelActionType.PERSIST_STATE },
						this._txAbort(this._state.channelId!, reason),
						...this.abortSplice(reason),
						{ type: ChannelActionType.ERROR, message: reason }
					];
				}
			}

			// Validate the peer's wallet witnesses BEFORE they are applied and
			// the batch below persists + broadcasts: one stack per peer input,
			// every signature verified against its negotiated prevout (the same
			// rules as the v2 open path). Refusing here fails the exchange with
			// a named error instead of persisting a splice tx that can never
			// confirm.
			const witnessProblem =
				this._validateSplicePeerWitnesses(peerWalletWitnesses);
			if (witnessProblem) {
				return this._spliceTxSigsRefusal(
					`invalid splice tx_signatures: ${witnessProblem}`
				);
			}

			// Verify the peer's 2-of-2 shared-input signature BEFORE the send
			// helper runs, for the same reason as the checks above (issue 350:
			// the later applyPeerSpliceSignature refusal discarded the send
			// helper's actions while its sent-flags mutations survived). An
			// invalid shared-input signature MUST send an error and fail the
			// channel (BOLT 2 splice tx_signatures).
			const sigProblem = this._verifySpliceSharedInputSig(peerSig);
			if (sigProblem) {
				return this._spliceTxSigsWireFailure(sigProblem);
			}

			const actions: ChannelAction[] = [];
			// We must have sent ours first (some peers send tx_signatures before us).
			actions.push(...this._maybeSendSpliceTxSigs());
			const tx = this.applyPeerSpliceSignature(peerSig, peerWalletWitnesses);
			if (!tx) {
				// Defensive only: every apply failure mode is pre-checked
				// above. Keep the send helper's actions in the batch so
				// dispatched actions always match its mutations, and keep the
				// outpoint watched (our signatures really left in this batch).
				return [
					...actions,
					...this._spliceTxSigsRefusal('invalid peer splice signature')
				];
			}

			// Record the splice outpoint and broadcast + watch it. Persist BEFORE
			// broadcasting so a crash cannot lose a splice tx the network has seen.
			const spliceTxid = Buffer.from(tx.getHash());
			this._state.spliceFundingTxid = spliceTxid;
			this._state.spliceFundingOutputIndex =
				this._spliceTx!.newFundingOutputIndex;
			this._syncSpliceInFlight({
				receivedTxSignatures: true,
				fullySigned: true,
				spliceTxHex: tx.toHex()
			});
			actions.push({ type: ChannelActionType.PERSIST_STATE });
			// Marked: this creates a funding output naming us. When WE signed
			// first the batch carries no tx_signatures of our own, so without
			// the mark nothing in it is barrier-class and the transaction would
			// reach the network ahead of the frame recording the splice.
			actions.push({
				type: ChannelActionType.BROADCAST_TX,
				tx: tx.toBuffer(),
				fundingCritical: true
			});
			actions.push(...this._recordPreSpliceSpendWatch(spliceTxid));
			actions.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: spliceTxid,
				fundingOutputIndex: this._spliceTx!.newFundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});

			// Zero-conf channels lock the splice immediately after tx_signatures
			// (BOLT 2): confirmation gating would idle the channel in exactly the
			// window zero-conf exists for. Ordinary channels lock at depth; the
			// confirmed check covers a confirmation that arrived while we were
			// missing the peer's signatures (e.g. it completed and broadcast
			// during a disconnect).
			if (
				this._isZeroConfChannelType() ||
				this._state.spliceInFlight?.confirmed
			) {
				actions.push(...this.sendSpliceLocked());
			}
			return actions;
		}

		// BOLT 2: tx_signatures MUST be ignored once either side has sent or
		// received channel_ready; the opening exchange is over. Checked before
		// the session requirement, and before anything with an effect: the
		// record is cleared at NORMAL while the live session object remains,
		// so without this gate a replay of the original (valid) message would
		// recreate the record, re-persist, rebroadcast, and pull the channel
		// from NORMAL back to AWAITING_FUNDING_CONFIRMED.
		if (this._state.localChannelReady || this._state.remoteChannelReady) {
			return [];
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}

		// Duplicate tx_signatures (retransmitted after a reconnect) when we are
		// already fully signed: benign no-op, mirroring the splice branch.
		if (this._state.v2InFlight?.receivedTxSignatures) {
			return [];
		}

		// BOLT 2 v2: tx_signatures MUST NOT be exchanged before the
		// commitment_signed round completes. Without this gate the old path
		// reached AWAITING_FUNDING_CONFIRMED with no commitment signature at
		// all — a funded channel with no unilateral exit.
		if (!this._v2SentCommitment || !this._v2ReceivedCommitment) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'tx_signatures before the commitment_signed exchange'
				}
			];
		}

		// Validate the peer's witnesses BEFORE they enter the session: the
		// count must match its inputs exactly, every stack must be able to
		// spend a segwit input, and signatures must commit to the whole
		// transaction (SIGHASH_ALL, or its taproot SIGHASH_DEFAULT
		// equivalent). Refusing here fails the negotiation cleanly instead
		// of advancing into a funding tx that can never be broadcast.
		const witnessProblem = this._validateV2PeerWitnesses(msg.witnesses || []);
		if (witnessProblem) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `invalid v2 tx_signatures: ${witnessProblem}`
				}
			];
		}

		const result = session.handlePeerWitnesses(msg.txid, msg.witnesses);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle peer witnesses'
				}
			];
		}

		// Update funding txid if not yet set (defensive: the commitment round
		// already set it). The v2 channel_id is the basepoint-derived id from
		// accept_channel2, not the funding outpoint — leave it untouched.
		if (!this._state.fundingTxid) {
			this._state.fundingTxid = Buffer.from(msg.txid);
			this._state.fundingOutputIndex = session.getFundingOutputIndex();
		}

		const actions: ChannelAction[] = [];
		// We may have been holding our own tx_signatures for the peer to sign
		// first — flush them now.
		actions.push(...this._maybeSendV2TxSigs());

		if (session.getState() === DualFundingState.AWAITING_CHANNEL_READY) {
			// Both witness sets are in hand (the flush above released ours, or
			// they had already left). The exchange only completes if the full
			// funding tx assembles and records: advancing anyway would mark
			// the peer's witnesses received while losing the only copy of
			// them on restart, and silence the next_funding announcement that
			// lets the peer resend them.
			if (!this._recordV2FullySigned()) {
				actions.push({
					type: ChannelActionType.ERROR,
					message:
						'v2 funding transaction could not be assembled from the exchanged signatures'
				});
				return actions;
			}
			this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
			// Persist BEFORE any broadcast.
			actions.push({ type: ChannelActionType.PERSIST_STATE });
			// When WE contributed inputs (lease selling) both witness sets are
			// now in hand: assemble and broadcast the funding tx ourselves
			// (mirrors the splice path; the opener usually broadcasts too, and
			// a duplicate broadcast is harmless).
			if (this._dualFundingContribution && this._state.pendingFundingTxHex) {
				// Same reason as the splice above: once our own
				// tx_signatures have been released this batch has nothing
				// barrier-class left to hold it.
				actions.push({
					type: ChannelActionType.BROADCAST_TX,
					tx: Buffer.from(this._state.pendingFundingTxHex, 'hex'),
					fundingCritical: true
				});
			}
			// Zero-conf v2: channel_ready right behind tx_signatures, mirroring
			// the v1 fast-tracks on funding_signed. Also flush a confirmation
			// that arrived while the exchange was still incomplete (the depth
			// callback is one-shot; see fundingConfirmed). A parked
			// confirmation names its attempt explicitly (candidates may
			// exist); the zero-conf fast-track has none to name.
			if (
				(this._state.zeroConfEnabled && this._state.trustedPeer) ||
				this._state.v2InFlight?.confirmed === true
			) {
				actions.push(
					...this.fundingConfirmed(
						this._state.v2InFlight?.confirmed
							? Buffer.from(this._state.v2InFlight.fundingTxid)
							: undefined
					)
				);
			}
		}

		return actions;
	}

	/**
	 * Assemble the full prevout set (script and value per input, in tx input
	 * order) for a negotiated transaction. Every interactive-tx input carries
	 * its serialized prev_tx, so the set can always be derived; the shared
	 * funding input of a splice has no prev_tx entry and is supplied via
	 * `sharedOverride`. Returns null when any prevout cannot be resolved,
	 * in which case nothing must be signed (BIP 341 sighashes commit to ALL
	 * prevouts).
	 */
	private _collectPrevouts(
		tx: import('bitcoinjs-lib').Transaction,
		inputs: Array<{
			prevTx?: Buffer;
			prevTxid?: Buffer;
			prevOutputIndex: number;
			prevTxVout?: number;
		}>,
		sharedOverride?: { index: number; script: Buffer; value: bigint }
	): { scripts: Buffer[]; values: bigint[] } | null {
		const scripts: Buffer[] = [];
		const values: bigint[] = [];
		for (let i = 0; i < tx.ins.length; i++) {
			if (sharedOverride && sharedOverride.index === i) {
				scripts.push(sharedOverride.script);
				values.push(sharedOverride.value);
				continue;
			}
			const txid = Buffer.from(tx.ins[i].hash);
			const vout = tx.ins[i].index;
			const source = inputs.find((inp) => {
				if (!inp.prevTx || inp.prevTx.length < 32) return false;
				return (
					extractTxidFromPrevTx(inp.prevTx).equals(txid) &&
					(inp.prevTxVout ?? inp.prevOutputIndex) === vout
				);
			});
			if (!source) return null;
			try {
				const prev = bitcoin.Transaction.fromBuffer(source.prevTx!);
				const out = prev.outs[vout];
				if (!out) return null;
				scripts.push(Buffer.from(out.script));
				values.push(BigInt(out.value));
			} catch {
				return null;
			}
		}
		return { scripts, values };
	}

	/**
	 * Assemble the fully-signed v2 funding tx: our witnesses on our inputs
	 * (signed via the live wallet closures, or replayed from the in-flight
	 * record after a restart), the peer's tx_signatures witnesses on theirs
	 * (both in ascending-serial input order). A side that contributed no
	 * inputs assembles too — every role must be able to (re)broadcast.
	 */
	private _assembleV2FundingTx(): Buffer | null {
		const session = this._state.dualFundingSession;
		if (!session) return null;
		const remote = session.getRemoteWitnesses();
		if (!remote) return null;
		const record = this._state.v2InFlight;
		const builder = session.getTxBuilder();
		if (!builder) {
			// Restored (builder-less) session: the negotiated tx and our
			// witnesses come from the durable record; no wallet closures are
			// needed or available. No re-signing — the stored witnesses were
			// produced over this exact transaction.
			if (!record) return null;
			if (record.ourWitnesses.length !== record.ourWalletInputIndices.length) {
				return null;
			}
			let tx: import('bitcoinjs-lib').Transaction;
			try {
				tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
			} catch {
				return null;
			}
			let r = 0;
			for (let i = 0; i < tx.ins.length; i++) {
				const pos = record.ourWalletInputIndices.indexOf(i);
				if (pos >= 0) {
					tx.setWitness(i, record.ourWitnesses[pos]);
				} else {
					if (r >= remote.length) return null;
					tx.setWitness(i, remote[r++]);
				}
			}
			return tx.toBuffer();
		}
		const built = this._v2NegotiatedTx();
		if (!built) return null;
		const sorted = [...builder.getInputs()].sort((a, b) =>
			a.serialId < b.serialId ? -1 : 1
		);
		if (sorted.length !== built.tx.ins.length) return null;
		const c = this._dualFundingContribution;
		// BIP 341: P2TR wallet inputs sign over ALL prevouts.
		const prevouts = c ? this._collectPrevouts(built.tx, sorted) : null;
		if (c && !prevouts) return null;
		let r = 0;
		for (let i = 0; i < built.tx.ins.length; i++) {
			// BOLT 2: initiator uses even serial ids, the acceptor odd.
			const ourInput =
				(sorted[i].serialId % 2n === 0n) === session.isInitiator();
			if (ourInput) {
				if (c) {
					const prevTxid = Buffer.from(built.tx.ins[i].hash);
					const vout = built.tx.ins[i].index;
					const w = c.inputs.find(
						(wi) =>
							extractTxidFromPrevTx(wi.prevTx).equals(prevTxid) &&
							wi.prevOutputIndex === vout
					);
					if (!w) return null;
					built.tx.setWitness(
						i,
						w.signWitness(built.tx, i, w.value, prevouts!)
					);
				} else if (record) {
					// Caller-driven flow: the witnesses that left as our
					// tx_signatures were recorded at release.
					const pos = record.ourWalletInputIndices.indexOf(i);
					if (pos < 0 || !record.ourWitnesses[pos]) return null;
					built.tx.setWitness(i, record.ourWitnesses[pos]);
				} else {
					return null;
				}
			} else {
				if (r >= remote.length) return null;
				built.tx.setWitness(i, remote[r++]);
			}
		}
		return built.tx.toBuffer();
	}

	/**
	 * Whether the negotiated channel_type carries option_zeroconf. RBF and
	 * splice-lock behavior both key off it: replacing an unconfirmed funding
	 * lineage that the peers already treat as usable creates fund-loss
	 * ambiguity, so BOLT 2 forbids tx_init_rbf on these channels and has the
	 * splice lock immediately after tx_signatures instead of at depth.
	 */
	private _isZeroConfChannelType(): boolean {
		return (
			this._state.channelType !== null &&
			FeatureFlags.fromBuffer(this._state.channelType).hasFeature(
				Feature.ZERO_CONF
			)
		);
	}

	/**
	 * Initiate RBF on the funding transaction (opener only).
	 *
	 * `newContribution` changes OUR funding_output_contribution for the
	 * replacement (BOLT 2 allows a different one per attempt); omitted keeps
	 * the recorded amount. A raised contribution arrives with the extra wallet
	 * inputs that fund it, selected and pledged by the caller: the registered
	 * set is only ever extended, never replaced, so the replacement still
	 * double-spends every previous attempt.
	 *
	 * Every refusal here is a bare ERROR action decided BEFORE anything
	 * reaches the wire, so a rejected request leaves the current attempt
	 * untouched on both sides.
	 */
	initiateTxRbf(
		newFeeratePerkw: number,
		newLocktime?: number,
		newContribution?: {
			fundingSatoshis: bigint;
			topUpInputs?: ISpliceWalletInput[];
		}
	): ChannelAction[] {
		// BOLT 2: a node MUST NOT send tx_init_rbf on an option_zeroconf
		// channel. Local misuse, so a plain ERROR action (no wire error).
		// Ahead of the lifecycle guard because it is the more specific reason
		// and reads only the negotiated channel type.
		if (this._isZeroConfChannelType()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'tx_init_rbf is forbidden on an option_zeroconf channel'
				}
			];
		}
		// The channel must still be OPENING. Every other guard below reads the
		// dual-funding SESSION, which a force close, a peer error or a
		// disconnect does not reset, so none of them notice that the channel
		// itself has left the opening flow. A raise whose wallet selection
		// resolves asynchronously can land arbitrarily late, and without this
		// the request would drag a FORCE_CLOSED, ERRORED or AWAITING_REESTABLISH
		// channel back into DUAL_FUNDING_V2 and start renegotiating a funding
		// tx whose commitment is already on the network.
		const lifecycle = this._state.state;
		if (
			lifecycle !== ChannelState.DUAL_FUNDING_V2 &&
			lifecycle !== ChannelState.AWAITING_TX_SIGNATURES &&
			lifecycle !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			lifecycle !== ChannelState.AWAITING_CHANNEL_READY
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `cannot RBF a v2 open in state ${lifecycle}`
				}
			];
		}
		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}
		// BOLT 2 window: a funding tx may be replaced any time before
		// channel_ready crosses in either direction. Broadcastable attempts
		// ARE replaceable (the spec's own window is a completed, broadcast,
		// unconfirmed attempt); superseded attempts stay tracked in
		// v2PreviousAttempts until one confirms.
		if (this._state.localChannelReady || this._state.remoteChannelReady) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF a v2 open after channel_ready'
				}
			];
		}
		// A confirmed attempt is final; BOLT 2 forbids replacing it (and any
		// RBF attempt in flight when a confirmation lands is abandoned).
		if (this._v2AnyAttemptConfirmed()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF a v2 open whose funding tx confirmed'
				}
			];
		}
		// Abort and RBF are mutually exclusive, never inferred from arrival
		// order: an abort of ours is outstanding (an operator abort, or the
		// rollback abort that unwound a failed ack), so no replacement of
		// the attempt it concerns may be requested before its echo.
		if (this._v2AbortPending || this._v2RollbackAbortPending) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF while a tx_abort is awaiting its echo'
				}
			];
		}
		// A restored (builder-less) session cannot renegotiate: the wallet
		// contribution closures did not survive the restart.
		if (!session.getTxBuilder()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF a v2 open restored after a restart'
				}
			];
		}

		if (!session.isInitiator()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Only initiator can initiate RBF'
				}
			];
		}
		// Only a session inside the replacement window can renegotiate:
		// negotiating, awaiting signatures, or completed-but-unconfirmed
		// (AWAITING_CHANNEL_READY, the BOLT 2 window; the channel_ready and
		// confirmation gates above bound it). The session applies the same
		// check when the ack arrives (initiateRbf), but by then tx_init_rbf
		// has already gone out and the peer's refusal errors the channel, so
		// anything later (COMPLETE) is refused here, before the wire.
		const sessionState = session.getState();
		if (
			sessionState !== DualFundingState.TX_NEGOTIATION &&
			sessionState !== DualFundingState.AWAITING_TX_SIGNATURES &&
			sessionState !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `cannot RBF: dual-funding session is not renegotiable in state ${sessionState}`
				}
			];
		}
		// One outstanding request at a time: a second tx_init_rbf would
		// overwrite the pending parameters, and the eventual ack would apply
		// the second request's feerate locally while the peer accepted the
		// first, pricing the two sides of one renegotiation differently.
		if (this._pendingRbfInit) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'an RBF request is already pending its ack'
				}
			];
		}
		// The previous request's ack already began a replacement round: until
		// the replacement records itself at its commitment persist, the
		// retained record still describes the REPLACED attempt, so a request
		// here would price its 25/24 floor against the wrong attempt and fail
		// at ack time with the peer already committed. One renegotiation at a
		// time; the guard reopens when the replacement's record lands.
		if (this._state.v2InFlight && this._v2RecordIsStaleRollback()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'an accepted RBF is still renegotiating; wait for the replacement attempt to be recorded'
				}
			];
		}
		// RBF replaces a COMPLETED attempt: the recorded one. Before the
		// record exists the negotiation is still in flight (and on this side
		// possibly still waiting for the wallet's asynchronous input
		// selection, whose stale contribution must never register into a
		// replacement builder); the record's existence proves the previous
		// attempt, drive and funding callback all ran to completion.
		if (!this._state.v2InFlight) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF: no completed funding attempt is recorded'
				}
			];
		}
		// A broadcastable attempt is only replaceable once its commitment
		// exchange completed: the superseded record stays tracked and may
		// confirm, and one without the peer's commitment signature has no
		// unilateral exit.
		if (
			this._v2RecordBroadcastable(this._state.v2InFlight) &&
			this._state.v2InFlight.remoteCommitmentSig === null
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot RBF before the commitment exchange completes'
				}
			];
		}
		// BOLT 2: the RBF feerate MUST be at least 25/24 of the previous
		// funding feerate. Validated here WITHOUT mutating anything: the
		// renegotiation only begins when the peer acks.
		const currentFeerate =
			this._state.v2InFlight?.fundingFeeratePerkw ??
			session.getLocalParams()?.fundingFeeratePerkw ??
			0;
		const floor = rbfFeerateFloor(currentFeerate);
		if (newFeeratePerkw < floor) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `RBF fee rate ${newFeeratePerkw} below the 25/24 floor ${floor}`
				}
			];
		}
		// Our own changed share is validated against the same bounds the
		// receive sites apply, before the request can reach the peer.
		const proposedContribution =
			newContribution?.fundingSatoshis ??
			this._state.v2InFlight.localContributionSats;
		if (newContribution) {
			if (!this._dualFundingContribution) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'cannot change the funding contribution: no wallet contribution is registered for this open'
					}
				];
			}
			if (proposedContribution <= 0n) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'RBF funding contribution must be greater than 0'
					}
				];
			}
			const refusal = this._v2RbfContributionRefusal(
				proposedContribution,
				this._state.v2InFlight.remoteContributionSats
			);
			if (refusal) {
				return [{ type: ChannelActionType.ERROR, message: refusal }];
			}
			// A pledge that expired while this attempt sat unsigned is handed
			// back to the wallet, so its own selection can re-offer a coin this
			// open ALREADY contributes. Spending it twice would build a funding
			// tx with a duplicate prevout: consensus-invalid, and nothing
			// downstream rejects it (the interactive-tx builder dedups on
			// serial id, and both audits would simply count the value twice).
			// Drop the duplicates here, where the request is still refusable;
			// if what remains cannot fund the raise, the affordability check
			// below refuses it.
			if (newContribution.topUpInputs?.length) {
				newContribution = {
					...newContribution,
					topUpInputs: this.unregisteredV2TopUpInputs(
						newContribution.topUpInputs
					)
				};
			}
		}
		// The wallet inputs must still cover our share at the new feerate.
		// Pure arithmetic over already-known values, so it belongs here: a
		// request the renegotiation could never afford is refused locally
		// instead of aborting the attempt after the peer acks. A raised
		// contribution is priced against the COMBINED set (registered plus
		// the top-up the caller selected for it), which is what acceptance
		// will install.
		const unaffordable = this._dualFundingAffordabilityError(
			newFeeratePerkw,
			newContribution
				? {
						contributionSats: proposedContribution,
						inputs: [
							...this._dualFundingContribution!.inputs,
							...(newContribution.topUpInputs ?? [])
						]
				  }
				: undefined
		);
		if (unaffordable) {
			return [{ type: ChannelActionType.ERROR, message: unaffordable }];
		}

		// NOTHING is replaced until tx_ack_rbf arrives: the current attempt
		// stays live and durable through the request window, so a disconnect
		// here resumes it on BOTH sides (the receiver only commits its own
		// replacement when it accepts, alongside the ack we never got).
		// handleTxAckRbf performs the actual renegotiation reset, and
		// revalidates this binding to the recorded attempt.
		const locktime = newLocktime ?? session.getLocalParams()?.locktime ?? 0;
		const msg: ITxInitRbfMessage = {
			channelId: this._v2ChannelId(),
			locktime,
			feerate: newFeeratePerkw
		};
		// BOLT 2: a contributor MUST state its funding_output_contribution.
		// A CHANGED amount is always stated, explicit zero included: an absent
		// TLV means "unchanged" between beignet peers, so omitting it is how
		// the unchanged case is expressed, never a withdrawal. Unchanged keeps
		// the legacy shape (restate when positive, omit when zero).
		const ourContribution = proposedContribution;
		if (
			ourContribution !== this._state.v2InFlight.localContributionSats ||
			ourContribution > 0n
		) {
			msg.fundingOutputContribution = ourContribution;
		}
		// Encode BEFORE any mutation: an out-of-range feerate/locktime throws
		// in the u32 writes, and a request that never reaches the wire must
		// not install the pending latch (a poisoned latch refuses every later
		// request as "already pending" until disconnect).
		let payload: Buffer;
		try {
			payload = encodeTxInitRbfMessage(msg);
		} catch (err) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `cannot RBF: ${(err as Error).message}`
				}
			];
		}
		this._pendingRbfInit = {
			feerate: newFeeratePerkw,
			locktime,
			fundingTxid: Buffer.from(this._state.v2InFlight!.fundingTxid),
			contribution: newContribution
		};
		// A fresh abort exchange may follow this request (the peer is free
		// to refuse it); a latch left over from a previous completed
		// exchange must not swallow that answer.
		this._txAbortSent = false;

		return [sendMsg(MessageType.TX_INIT_RBF, payload)];
	}

	/**
	 * Unwind a failed v2 negotiation round. During an RBF renegotiation the
	 * retained rollback record IS the previous attempt: roll back to it
	 * (builder-less, restart-equivalent) and tell the peer with tx_abort,
	 * whose retained record rolls IT back the same way; both sides converge
	 * on the shared previous attempt. Outside a renegotiation there is
	 * nothing to return to and the original-attempt unwind
	 * (_abortV2Negotiation) applies.
	 */
	private _unwindV2NegotiationOrRollback(reason: string): ChannelAction[] {
		if (this._state.v2InFlight && this._v2RecordIsStaleRollback()) {
			this._rollbackToRetainedV2Attempt();
			return [
				{ type: ChannelActionType.PERSIST_STATE },
				this._txAbort(this._v2ChannelId(), reason),
				{ type: ChannelActionType.ERROR, message: reason }
			];
		}
		return this._abortV2Negotiation(reason);
	}

	/**
	 * Roll a renegotiation back to the RETAINED previous attempt: drop the
	 * live session and driver, resume from the record, and re-point the
	 * funding outpoint at it. The resumed channel state is attempt-aware: a
	 * previous attempt whose witnesses left is waiting on the chain again
	 * (AWAITING_FUNDING_CONFIRMED), an incomplete one on the peer
	 * (AWAITING_TX_SIGNATURES). restoreV2InFlight only repairs the outpoint
	 * when unset, so it is overwritten here explicitly: the replaced
	 * renegotiation may have re-pointed it at the replacement.
	 */
	/**
	 * Make a v2 attempt record the ACTIVE one on channel state: the funding
	 * outpoint the commitment machinery reads, and the peer's commitment
	 * signature for exactly this attempt. Each attempt's commitment signs a
	 * different funding outpoint, so retaining another attempt's
	 * remoteCommitmentSignature would leave forceClose broadcasting a
	 * commitment that spends an output that can never exist. A record whose
	 * commitment exchange never completed activates with a null signature:
	 * no unilateral exit exists for it, and forceClose refuses rather than
	 * signs garbage. Every rollback/adoption path MUST route through here.
	 *
	 * Also restores the amounts the attempt was negotiated at (see
	 * _restoreV2RecordSnapshot): with per-attempt contributions the outpoint
	 * and the signature are only half of what identifies an attempt.
	 */
	private _activateV2Record(record: IV2InFlight): void {
		this._state.fundingTxid = Buffer.from(record.fundingTxid);
		this._state.fundingOutputIndex = record.fundingOutputIndex;
		this._state.remoteCommitmentSignature = record.remoteCommitmentSig
			? Buffer.from(record.remoteCommitmentSig)
			: null;
		// A v2 opening commitment (#0) carries no HTLCs.
		this._state.remoteHtlcSignatures = [];
		this._restoreV2RecordSnapshot(record);
	}

	/**
	 * Derive BOTH v2 channel reserves from the current capacity.
	 *
	 * Called at the two open sites, again whenever a liquidity-ads lease fee
	 * grows the capacity those sites derived from, and on every accepted RBF
	 * contribution change. localConfig.dustLimitSatoshis is the dust limit the
	 * v2 handshake advertises (both the opener's params and the acceptor's
	 * accept_channel2 are built from config.localConfig), so enforcement matches
	 * the advertisement.
	 */
	private _deriveV2ChannelReserves(): void {
		const capacity = this._state.fundingSatoshis;
		const ourDust = this._state.localConfig.dustLimitSatoshis;
		const peerDust = this._state.remoteConfig.dustLimitSatoshis;
		this._state.remoteConfig = {
			...this._state.remoteConfig,
			channelReserveSatoshis: v2ReserveWeKeep(capacity, ourDust, peerDust)
		};
		this._state.localConfig = {
			...this._state.localConfig,
			channelReserveSatoshis: v2ReserveWeEnforce(capacity, ourDust, peerDust)
		};
		this._state.channelReserveVersion = ENFORCED_RESERVE_VERSION;
	}

	/**
	 * Both channel reserves for a given v2 attempt.
	 *
	 * localChannelReserveSatoshis is optional independently of the amounts group
	 * it sits in: rows written by the version that introduced per-attempt
	 * amounts carry the other four fields and not this one. Its absence marks a
	 * row whose remoteChannelReserveSatoshis was ALSO computed by that version,
	 * i.e. by the capped v1 helper, from the peer's dust limit alone and, on a
	 * leased open, from the pre-lease-fee capacity. Restoring that value
	 * verbatim would reinstate exactly the defects this derivation fixes, so
	 * such a row re-derives BOTH sides. Reserves are a pure function of capacity
	 * and the dust limits and never enter the commitment, so re-deriving cannot
	 * invalidate the attempt's stored signature.
	 */
	private _v2RecordReserves(record: IV2InFlight): {
		ours: bigint;
		theirs: bigint;
	} {
		const ourDust = this._state.localConfig.dustLimitSatoshis;
		const peerDust = this._state.remoteConfig.dustLimitSatoshis;
		if (record.localChannelReserveSatoshis === undefined) {
			return {
				ours: v2ReserveWeKeep(record.fundingSatoshis!, ourDust, peerDust),
				theirs: v2ReserveWeEnforce(record.fundingSatoshis!, ourDust, peerDust)
			};
		}
		return {
			ours: record.remoteChannelReserveSatoshis!,
			theirs: record.localChannelReserveSatoshis
		};
	}

	/**
	 * Restore the capacity, balances and capacity-derived reserves that a v2
	 * attempt was negotiated at.
	 *
	 * BOLT 2 lets each RBF attempt carry a different
	 * funding_output_contribution, so these values are per-attempt: an attempt
	 * reactivated at another attempt's amounts would rebuild its commitment #0
	 * with a different funding value and different outputs, and the peer's
	 * stored signature covers none of it.
	 *
	 * Records written before contribution changes existed carry no snapshot.
	 * Those attempts all shared one set of amounts, so live state already
	 * holds theirs and there is nothing to restore. Their RESERVES still are
	 * not derived, though: such a row predates the v2 open deriving either one,
	 * so it carries the node's configured constant on both sides for the life
	 * of the channel and neither this method's snapshot branch nor the load-time
	 * repairs (which defer to it for any row with a live record) ever reach it.
	 * Derive them from live capacity, which IS this attempt's capacity by the
	 * same argument. Safe against the stored signature: a reserve is a policy
	 * value that no commitment builder reads (issue #387).
	 */
	private _restoreV2RecordSnapshot(record: IV2InFlight): void {
		if (record.fundingSatoshis === undefined) {
			this._deriveV2ChannelReserves();
			return;
		}
		this._state.fundingSatoshis = record.fundingSatoshis;
		this._state.localBalanceMsat = record.localBalanceMsat!;
		this._state.remoteBalanceMsat = record.remoteBalanceMsat!;
		const reserves = this._v2RecordReserves(record);
		this._state.remoteConfig = {
			...this._state.remoteConfig,
			channelReserveSatoshis: reserves.ours
		};
		this._state.localConfig = {
			...this._state.localConfig,
			channelReserveSatoshis: reserves.theirs
		};
		this._state.channelReserveVersion = ENFORCED_RESERVE_VERSION;
		// Our wallet contribution funds the funding output, so it tracks the
		// attempt too: the change output and the underfunded check are both
		// derived from it.
		if (
			this._dualFundingContribution &&
			this._state.leaseFeeSats === undefined
		) {
			this._dualFundingContribution.contributionSats =
				record.localContributionSats;
		}
	}

	/**
	 * Return the registered wallet contribution to the shape the given attempt
	 * was negotiated at, handing back any inputs that attempt does not spend.
	 *
	 * Only a raised contribution ever extends the registered set, and the
	 * extension belongs to the attempt that raised it: resuming an earlier
	 * attempt with those inputs still registered would misprice the next
	 * affordability check and keep coins frozen for a replacement that no
	 * longer exists. Every attempt spends ALL of the inputs registered for it,
	 * so the attempt's own transaction identifies its set exactly and no extra
	 * durable field is needed.
	 *
	 * Skipped for leased opens, whose contributionSats carries the lease fee
	 * the record does not, and whose split cannot change anyway.
	 */
	/**
	 * A wallet input's outpoint in INTERNAL byte order, matching the `hash`
	 * field of a parsed transaction input so the two can be compared directly.
	 */
	private _walletInputOutpointKey(input: ISpliceWalletInput): string {
		return `${extractTxidFromPrevTx(input.prevTx).toString('hex')}:${
			input.prevOutputIndex
		}`;
	}

	/**
	 * Of `inputs`, those this channel does NOT already contribute to its v2
	 * open: the only ones a caller may hand back to the wallet.
	 *
	 * A refused raise must release exactly the coins nothing spends. Its
	 * selection can legitimately include an outpoint this open ALREADY
	 * registered (the wallet frees a pledge whose TTL lapsed while the attempt
	 * sat unsigned, so its next selection is free to offer that coin again),
	 * and releasing THAT unfreezes a coin the live funding transaction
	 * depends on: whatever spends it next orphans the channel, which is the
	 * outcome pledges exist to prevent. The channel answers this because only
	 * it knows the registered set.
	 */
	unregisteredV2TopUpInputs(
		inputs: ISpliceWalletInput[]
	): ISpliceWalletInput[] {
		if (!inputs.length) return [];
		const registered = new Set(
			(this._dualFundingContribution?.inputs ?? []).map((i) =>
				this._walletInputOutpointKey(i)
			)
		);
		return inputs.filter(
			(i) => !registered.has(this._walletInputOutpointKey(i))
		);
	}

	private _restoreDualFundingContributionFor(record: IV2InFlight): void {
		const c = this._dualFundingContribution;
		if (!c || this._state.leaseFeeSats !== undefined) return;
		let spent: Set<string>;
		try {
			const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
			spent = new Set(
				tx.ins.map((i) => `${Buffer.from(i.hash).toString('hex')}:${i.index}`)
			);
		} catch {
			// Unreadable record: keep the registered set as it is rather than
			// drop inputs the resumed attempt may still need. The wallet's
			// pledge TTL releases anything genuinely orphaned.
			return;
		}
		const kept: ISpliceWalletInput[] = [];
		for (const input of c.inputs) {
			const outpoint = this._walletInputOutpointKey(input);
			if (spent.has(outpoint)) kept.push(input);
			else this._danglingV2TopUpInputs.push(input);
		}
		c.inputs = kept;
		c.contributionSats = record.localContributionSats;
		c.feeratePerKw = record.fundingFeeratePerkw;
		this._dualFundingContribs = null;
		this._dualFundingContribIndex = 0;
	}

	/**
	 * Hand back the pledges of a contribution raise that never took effect.
	 * Called wherever a pending RBF request is dropped without being applied.
	 */
	private _releasePendingRbfTopUp(): void {
		this._stashTopUpInputs(this._pendingRbfInit?.contribution?.topUpInputs);
	}

	/** As above, for arms that captured the request before clearing the latch. */
	private _stashTopUpInputs(inputs?: ISpliceWalletInput[]): void {
		if (inputs?.length) this._danglingV2TopUpInputs.push(...inputs);
	}

	/**
	 * Wallet inputs this channel selected for a contribution raise that never
	 * became part of an attempt. The manager drains this and asks the wallet
	 * to unfreeze them; the provider's pledge TTL is the backstop for windows
	 * no drain reaches (a crash between selection and registration).
	 */
	takeDanglingV2TopUpPledgeOutpoints(
		clear = true
	): Array<{ txid: string; vout: number }> {
		if (!this._danglingV2TopUpInputs.length) return [];
		const outpoints: Array<{ txid: string; vout: number }> = [];
		for (const input of this._danglingV2TopUpInputs) {
			try {
				outpoints.push({
					txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
					vout: input.prevOutputIndex
				});
			} catch {
				// Unreadable prevTx: nothing to name, TTL handles it.
			}
		}
		// A caller that cannot commit the rollback these inputs belong to
		// peeks instead, so the stash survives for the batch that does.
		if (clear) this._danglingV2TopUpInputs = [];
		return outpoints;
	}

	/**
	 * Why a proposed RBF contribution split must be refused, or null when it
	 * is acceptable.
	 *
	 * BOLT 2 allows each attempt its own funding_output_contribution, so the
	 * split is renegotiable, but the resulting channel still has to be one we
	 * would have opened: every bound here is the v2 equivalent of a check the
	 * v1 open path makes at accept time (validateOpenChannelParams is v1-only,
	 * and a v2 open has no configured minimum).
	 *
	 * Refusals are attempt-scoped at both receive sites: the replacement dies,
	 * both sides keep the recorded attempt, and the channel lives on.
	 */
	private _v2RbfContributionRefusal(
		localSats: bigint,
		remoteSats: bigint
	): string | null {
		const record = this._state.v2InFlight;
		if (
			record &&
			localSats === record.localContributionSats &&
			remoteSats === record.remoteContributionSats
		) {
			// Unchanged: the pre-existing path, nothing to validate.
			return null;
		}
		if (localSats < 0n || remoteSats < 0n) {
			// funding_output_contribution rides a signed 64-bit TLV, so a
			// negative amount decodes cleanly and must be rejected here.
			return 'RBF funding_output_contribution must not be negative';
		}
		if (this._state.leaseFeeSats !== undefined) {
			// The lease fee and the will_fund signature were made over the
			// ORIGINAL amounts, and the lessor's balance carries that fee.
			// Renegotiating the split would invalidate the purchase both sides
			// already agreed on.
			return 'changing the funding contribution of a leased v2 open is not supported';
		}
		const newCapacity = localSats + remoteSats;
		if (newCapacity > this._maxFundingSatoshis) {
			return `post-RBF capacity ${newCapacity} exceeds maximum ${this._maxFundingSatoshis}`;
		}
		const dustFloor = bigIntMax(
			bigIntMax(
				this._state.localConfig.dustLimitSatoshis,
				this._state.remoteConfig.dustLimitSatoshis
			),
			DUST_LIMIT_SATS
		);
		if (newCapacity < dustFloor) {
			// Caught at tx_complete anyway, but refusing at the RBF message
			// keeps it attempt-scoped instead of failing mid-exchange.
			return `post-RBF capacity ${newCapacity} is below the funding-output dust floor ${dustFloor}`;
		}
		const isInitiator =
			record?.isInitiator ??
			this._state.dualFundingSession?.isInitiator() ??
			false;
		// A non-lease v2 open has no push and no HTLCs at commitment #0, so each
		// side's balance IS its contribution.
		const viability = this._v2InitialCommitmentRefusal(
			localSats,
			remoteSats,
			isInitiator
		);
		return viability === null ? null : `post-RBF ${viability}`;
	}

	/**
	 * BOLT 2's admission rules for the commitment a v2 negotiation is about to
	 * build, as a refusal reason or null.
	 *
	 * open_channel2 and accept_channel2 inherit the open_channel/accept_channel
	 * requirements ("Rationale and Requirements are the same as ... with the
	 * following additions"), so the two receiver MUST-fails on the initial
	 * commitment apply to a v2 open exactly as validateOpenChannelParams
	 * enforces them for v1: the funder must afford the commitment fee, and both
	 * outputs must not be at or below the channel reserve. The same rules gate
	 * an RBF replacement, whose split is renegotiated from scratch.
	 *
	 * Takes each side's commitment #0 BALANCE in sats (which carries a lease fee
	 * where there is one), and who pays the commitment fee. The opener alone
	 * funds the fee and both anchors; a v2 open has no push_msat to soften it,
	 * which is also what refuses an opener dropping its contribution to nothing.
	 */
	private _v2InitialCommitmentRefusal(
		localSats: bigint,
		remoteSats: bigint,
		weAreOpener: boolean
	): string | null {
		const capacity = localSats + remoteSats;
		const commitCostSats = funderCommitmentCostSats(
			this._state.commitmentFeeratePerkw,
			0,
			this._state.channelType
		);
		const openerSats = weAreOpener ? localSats : remoteSats;
		if (openerSats < commitCostSats) {
			return `opener contribution ${openerSats} cannot afford the initial commitment fee ${commitCostSats}`;
		}
		const ourDust = this._state.localConfig.dustLimitSatoshis;
		const peerDust = this._state.remoteConfig.dustLimitSatoshis;
		const ourReserve = v2ReserveWeKeep(capacity, ourDust, peerDust);
		const theirReserve = v2ReserveWeEnforce(capacity, ourDust, peerDust);
		const ourSatsAfterFee = weAreOpener
			? localSats - commitCostSats
			: localSats;
		const theirSatsAfterFee = weAreOpener
			? remoteSats
			: remoteSats - commitCostSats;
		// BOLT 2 MUST-fail on "less than or equal to", each side against ITS own
		// reserve (what the two peers derive for themselves).
		if (ourSatsAfterFee <= ourReserve && theirSatsAfterFee <= theirReserve) {
			return `capacity ${capacity} leaves both sides at or below their channel reserve (ours ${ourReserve}, theirs ${theirReserve})`;
		}
		// And no commitment may be born with every output trimmed. The rule
		// above does not cover it once the dust limits differ: each commitment
		// trims at ITS OWN holder's limit, and the reserve we enforce on the
		// peer deliberately floors at the LOWER one, so a balance above that
		// reserve can still be dust in the commitment we hold. A transaction
		// with no outputs is invalid, so the side holding it has no unilateral
		// exit at all while the peer keeps a broadcastable one.
		//
		// STRICTLY below, because commitment #0 carries no HTLCs and an anchor
		// output only exists alongside a surviving main output (BOLT 3), so
		// "either commitment is empty" is exactly
		// max(ourSatsAfterFee, theirSatsAfterFee) < max(ourDust, peerDust):
		// the builder trims on `amount < dust_limit` and keeps an output whose
		// value lands exactly ON the limit (script/commitment.ts). At equality the
		// LARGER balance clears both dust limits, so it is an output in both
		// commitments and neither is empty; the smaller one is trimmed from at
		// least the commitment of whichever peer has the larger dust limit, and
		// may still survive in the other. BOLT 2 allows that for the same reason
		// the reserve rule above is an AND: one exit is enough to unilaterally
		// close (issue #388).
		const dustFloor = bigIntMax(ourDust, peerDust);
		if (bigIntMax(ourSatsAfterFee, theirSatsAfterFee) < dustFloor) {
			return `capacity ${capacity} trims every commitment #0 output at the ${dustFloor} dust limit`;
		}
		return null;
	}

	/**
	 * Apply an accepted RBF contribution change to live state.
	 *
	 * Called at renegotiation ACCEPTANCE (tx_ack_rbf received, or tx_init_rbf
	 * accepted), once every refusal has been decided, and before anything
	 * sizes the replacement: the funding output, commitment #0 and the
	 * completed-tx audits all read these live values.
	 *
	 * Non-lease v2 opens have no push and no HTLCs at commitment #0, so each
	 * side's balance is exactly its contribution; leased opens keep the
	 * refusal, because their balances also carry the lease fee the will_fund
	 * signature was made over.
	 */
	private _applyV2ContributionChange(
		newLocalSats: bigint,
		newRemoteSats: bigint
	): void {
		const retained = this._state.v2InFlight;
		// A record written before snapshots existed is about to become the
		// rollback target for an attempt with DIFFERENT amounts, so capture
		// the values it was negotiated at (still live, since nothing else
		// changes them) before they are overwritten. Without this the
		// rollback would restore nothing and resume the previous attempt at
		// the replacement's amounts.
		if (retained && retained.fundingSatoshis === undefined) {
			retained.fundingSatoshis = this._state.fundingSatoshis;
			retained.localBalanceMsat = this._state.localBalanceMsat;
			retained.remoteBalanceMsat = this._state.remoteBalanceMsat;
			retained.remoteChannelReserveSatoshis =
				this._state.remoteConfig.channelReserveSatoshis;
			// localChannelReserveSatoshis is deliberately NOT captured: on a
			// channel opened before the reserve we enforce was derived at all,
			// live localConfig holds the static config value, and snapshotting
			// that would restore it durably on the next rollback. Left absent,
			// _v2RecordReserves re-derives BOTH reserves from the attempt's
			// capacity, which is also what the stale remote value above needs.
		}
		this._state.fundingSatoshis = newLocalSats + newRemoteSats;
		this._state.localBalanceMsat = newLocalSats * 1000n;
		this._state.remoteBalanceMsat = newRemoteSats * 1000n;
		this._deriveV2ChannelReserves();
		if (this._dualFundingContribution) {
			this._dualFundingContribution.contributionSats = newLocalSats;
		}
	}

	/**
	 * The state a CONFIRMED superseded v2 RBF attempt contributes to a force
	 * close, or null when no such attempt is waiting to be adopted.
	 *
	 * The chain watcher's depth callback is one-shot. When it fires while the
	 * channel cannot consume it (disconnected, so AWAITING_REESTABLISH), the
	 * winning attempt is only STAMPED confirmed on its record, and the live
	 * outpoint still names the replacement it beat. A force close from there
	 * would spend a funding output that lost the race and can never exist,
	 * producing an exit the network rejects while the close reports success.
	 *
	 * Pure: like _computeSpliceAdoption it only builds the view, so
	 * prepareForceClose can still refuse without having moved the channel.
	 */
	private _computeV2ConfirmedAdoption(): Partial<IChannelState> | null {
		const previous = this._state.v2PreviousAttempts;
		if (!previous?.length) return null;
		// The current attempt confirming is the ordinary case and needs no
		// adoption: it is already the active one.
		if (this._state.v2InFlight?.confirmed) return null;
		const index = previous.findIndex((rec) => rec.confirmed);
		if (index < 0) return null;
		const adopted = previous[index];
		const fields: Partial<IChannelState> = {
			v2InFlight: adopted,
			v2PreviousAttempts: undefined,
			fundingTxid: Buffer.from(adopted.fundingTxid),
			fundingOutputIndex: adopted.fundingOutputIndex,
			remoteCommitmentSignature: adopted.remoteCommitmentSig
				? Buffer.from(adopted.remoteCommitmentSig)
				: null,
			// A v2 opening commitment (#0) carries no HTLCs.
			remoteHtlcSignatures: [],
			pendingFundingTxHex: undefined
		};
		// The amounts this attempt's commitment was signed at; absent on
		// records predating per-attempt contributions, whose amounts are the
		// live ones already.
		if (adopted.fundingSatoshis !== undefined) {
			fields.fundingSatoshis = adopted.fundingSatoshis;
			fields.localBalanceMsat = adopted.localBalanceMsat;
			fields.remoteBalanceMsat = adopted.remoteBalanceMsat;
			const reserves = this._v2RecordReserves(adopted);
			fields.remoteConfig = {
				...this._state.remoteConfig,
				channelReserveSatoshis: reserves.ours
			};
			fields.localConfig = {
				...this._state.localConfig,
				channelReserveSatoshis: reserves.theirs
			};
			fields.channelReserveVersion = ENFORCED_RESERVE_VERSION;
		}
		return fields;
	}

	private _rollbackToRetainedV2Attempt(): void {
		this._state.dualFundingSession?.abort();
		this._state.dualFundingSession = null;
		this._resetV2Driver();
		this._releasePendingRbfTopUp();
		this._pendingRbfInit = null;
		this.restoreV2InFlight();
		const record = this._state.v2InFlight;
		if (record) {
			this._activateV2Record(record);
			this._restoreDualFundingContributionFor(record);
			this._state.state = this._v2StateForRecord(record);
		} else {
			this._state.state = ChannelState.AWAITING_TX_SIGNATURES;
		}
	}

	/**
	 * Abandon an UNSIGNED, non-broadcastable replacement attempt that has
	 * already recorded itself (its commitment persist ran, so the retained-
	 * rollback machinery no longer applies) and resume the newest superseded
	 * attempt. Safe exactly because nothing of the abandoned replacement can
	 * appear on chain: our witnesses never left and the peer cannot complete
	 * it alone (the caller checks both). Used when the peer tells us to
	 * forget the replacement (tx_abort, or a reestablish that no longer
	 * names it).
	 */
	private _popToPreviousV2Attempt(): void {
		const previous = this._state.v2PreviousAttempts!;
		const record = previous[previous.length - 1];
		this._state.v2PreviousAttempts =
			previous.length > 1 ? previous.slice(0, -1) : undefined;
		this._state.dualFundingSession?.abort();
		this._state.dualFundingSession = null;
		this._resetV2Driver();
		this._state.v2InFlight = record;
		this._activateV2Record(record);
		this._restoreDualFundingContributionFor(record);
		this._state.pendingFundingTxHex = record.fullySigned
			? record.fundingTxHex
			: undefined;
		this.restoreV2InFlight();
		this._state.state = this._v2StateForRecord(record);
	}

	/**
	 * Whether the CURRENT record is an abandonable replacement: unsigned in
	 * both directions, not broadcastable on its own, with superseded
	 * attempts still tracked behind it. The one shape a peer may legally
	 * tell us to forget after the replacement recorded itself.
	 */
	private _v2ReplacementAbandonable(): boolean {
		const record = this._state.v2InFlight;
		return !!(
			record &&
			this._state.v2PreviousAttempts?.length &&
			!record.sentTxSignatures &&
			!record.receivedTxSignatures &&
			!this._v2RecordBroadcastable(record)
		);
	}

	/**
	 * A SUPERSEDED attempt reached depth: adopt it as the channel's funding.
	 * Every other attempt (the current one included) is dead on chain — each
	 * replacement double-spends all of its predecessors — so whatever
	 * negotiation the adoption kills is abandoned: an unsigned replacement
	 * gets its tx_abort abandon signal (BOLT 2 abandons an RBF attempt when
	 * a previous transaction confirms; the latch and released-signatures
	 * guards keep the single-abort and no-abort-after-tx_signatures rules),
	 * a replacement whose signatures left simply stops mattering. Leaves the
	 * channel at AWAITING_FUNDING_CONFIRMED on the adopted attempt; the
	 * caller runs the ready flow.
	 */
	private _v2AdoptPreviousAttempt(index: number): ChannelAction[] {
		const adopted = this._state.v2PreviousAttempts![index];
		const canAbort = !this._v2TxSigsReleased && !this._txAbortSent;
		this._state.dualFundingSession?.abort();
		this._state.dualFundingSession = null;
		this._resetV2Driver();
		this._releasePendingRbfTopUp();
		this._pendingRbfInit = null;
		this._state.v2InFlight = adopted;
		this._state.v2PreviousAttempts = undefined;
		this._activateV2Record(adopted);
		this._restoreDualFundingContributionFor(adopted);
		// The staged rebroadcast hex tracked the replaced attempt; the
		// adopted tx is on chain, so it only matters when fully signed (the
		// depth watcher retires it against the adopted txid).
		this._state.pendingFundingTxHex = adopted.fullySigned
			? adopted.fundingTxHex
			: undefined;
		this.restoreV2InFlight();
		this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		const actions: ChannelAction[] = [
			{ type: ChannelActionType.PERSIST_STATE }
		];
		if (canAbort) {
			actions.push(
				this._txAbort(
					this._v2ChannelId(),
					'a previous funding attempt confirmed; the replacement is abandoned'
				)
			);
		}
		return actions;
	}

	/**
	 * The peer accepted our tx_init_rbf: the renegotiation begins HERE. The
	 * previous attempt survived the request window (durably and in memory),
	 * so a disconnect before this ack resumed it on both sides; from the ack
	 * onward both sides have agreed to replace it, and the per-attempt record
	 * clears durably on this side exactly as the receiver's cleared with its
	 * accept.
	 */
	handleTxAckRbf(msg?: ITxAckRbfMessage): ChannelAction[] {
		const session = this._state.dualFundingSession;
		const pending = this._pendingRbfInit;
		this._pendingRbfInit = null;
		if (!session || !pending) {
			// An unsolicited ack, or one for a request this connection no
			// longer remembers (the pending marker dies with the connection):
			// it acknowledges nothing. The peer's view converges over
			// reestablish.
			this._stashTopUpInputs(pending?.contribution?.topUpInputs);
			return [];
		}
		// Revalidate the binding: the renegotiation must replace exactly the
		// attempt the request named. If the record is gone, tracks a
		// different transaction, or the window closed while the request was
		// in flight (channel_ready crossed, or an attempt confirmed — BOLT 2
		// abandons an RBF attempt in both cases), beginning the renegotiation
		// would strand or erase an attempt the peer can still act on. Unwind
		// the accepted request on the wire instead; the peer retained its
		// rollback record and returns to the shared attempt.
		const bound = this._state.v2InFlight;
		if (
			!bound ||
			!bound.fundingTxid.equals(pending.fundingTxid) ||
			this._state.localChannelReady ||
			this._state.remoteChannelReady ||
			this._v2AnyAttemptConfirmed()
		) {
			// The abort expects the peer's echo; serialize the exchange so a
			// new RBF or operator abort cannot overlap it (the delayed echo
			// would be taken for the newer abort's answer).
			this._v2RollbackAbortPending = true;
			this._stashTopUpInputs(pending.contribution?.topUpInputs);
			return [
				this._txAbort(
					this._v2ChannelId(),
					'RBF request no longer applies to the recorded attempt'
				)
			];
		}
		// The peer's contribution for this attempt (see handleTxInitRbf for the
		// absent-means-unchanged rule), and ours as the request proposed it.
		// An out-of-bounds ack unwinds on the wire and keeps the recorded
		// attempt; our own side was already validated before the request left,
		// so only a misbehaving peer reaches a refusal here.
		const newRemoteContribution =
			msg?.fundingOutputContribution ?? bound.remoteContributionSats;
		const newLocalContribution =
			pending.contribution?.fundingSatoshis ?? bound.localContributionSats;
		const contributionRefusal = this._v2RbfContributionRefusal(
			newLocalContribution,
			newRemoteContribution
		);
		if (contributionRefusal) {
			this._v2RollbackAbortPending = true;
			this._stashTopUpInputs(pending.contribution?.topUpInputs);
			return [this._txAbort(this._v2ChannelId(), contributionRefusal)];
		}
		const contributionChanged =
			newLocalContribution !== bound.localContributionSats ||
			newRemoteContribution !== bound.remoteContributionSats;
		// The acceptor may require confirmed inputs for the replacement. Our
		// registered inputs are reused verbatim, and a raise contributes the
		// top-up the request selected as well, so BOTH sets have to satisfy it
		// (the wallet may return unconfirmed coins). Unwind now instead of
		// failing mid-exchange on a tx_add_input the peer must reject.
		if (
			msg?.requireConfirmedInputs &&
			[
				...(this._dualFundingContribution?.inputs ?? []),
				...(pending.contribution?.topUpInputs ?? [])
			].some((i) => i.confirmed === false)
		) {
			this._v2RollbackAbortPending = true;
			this._stashTopUpInputs(pending.contribution?.topUpInputs);
			return [
				this._txAbort(
					this._v2ChannelId(),
					'require_confirmed_inputs not satisfied'
				)
			];
		}
		const result = session.initiateRbf(
			pending.feerate,
			pending.locktime,
			contributionChanged
				? {
						localSats: newLocalContribution,
						remoteSats: newRemoteContribution
				  }
				: undefined
		);
		if (!result.ok) {
			// The peer accepted and is waiting for the renegotiation's first
			// tx_add_*; a bare local error would strand it. Unwind on the
			// wire (mirroring handleTxInitRbf's session-failure arm): the
			// peer's retained rollback record returns it to the shared
			// previous attempt, and its echo lands in the sent-latch swallow.
			// initiateRbf fails before mutating anything, so the current
			// attempt stays fully live here: no rollback, no persist, and no
			// _v2AbortPending (nothing is torn down at the echo). The
			// rollback latch serializes the exchange instead: no new RBF or
			// operator abort may overlap this abort before its echo. The
			// stale-record guard in initiateTxRbf keeps this arm a belt.
			this._v2RollbackAbortPending = true;
			this._stashTopUpInputs(pending.contribution?.topUpInputs);
			const reason = result.error || 'Failed to begin the RBF renegotiation';
			return [
				this._txAbort(this._v2ChannelId(), reason),
				{ type: ChannelActionType.ERROR, message: reason }
			];
		}
		this._state.state = ChannelState.DUAL_FUNDING_V2;
		// The previous attempt's record is RETAINED here too, symmetric with
		// the receiver: it is replaced only by the NEW attempt's record, in
		// the single commitment persist that makes the replacement durable
		// (_syncV2InFlight). There is no separate clear-write to fail, so a
		// persistence failure anywhere leaves BOTH sides rolling back to the
		// shared previous attempt. Only the driver resets.
		this._resetV2Driver();
		// Apply the accepted split before anything sizes the replacement:
		// _computeDualFundingContributions below builds the shared funding
		// output from the live capacity and our change from the live
		// contribution. A failure after this point unwinds through
		// _unwindV2NegotiationOrRollback, which restores the retained
		// attempt's amounts along with its outpoint.
		if (contributionChanged) {
			this._applyV2ContributionChange(
				newLocalContribution,
				newRemoteContribution
			);
		}
		// The renegotiation restarts the interactive-tx exchange from
		// nothing: reprice the registered contribution at the accepted
		// feerate and drop the derived list so it re-derives against the
		// fresh builder (its serial ids died with the old one). The first
		// tx_add_* rides behind the persist below, so a failed commit
		// withholds it and the ack boundary stays the durable one.
		if (this._dualFundingContribution) {
			// A raised contribution is funded by the inputs the request
			// selected on top of the registered set; they were pledged when
			// the request was made and are adopted here, at acceptance.
			if (pending.contribution?.topUpInputs?.length) {
				this._dualFundingContribution.inputs = [
					...this._dualFundingContribution.inputs,
					...pending.contribution.topUpInputs
				];
			}
			this._dualFundingContribution.feeratePerKw = pending.feerate;
			this._dualFundingContribs = null;
			this._dualFundingContribIndex = 0;
			const derived = this._computeDualFundingContributions();
			if (derived) {
				// A bare local error would leave the peer waiting forever
				// for a tx_add_* that never comes. Roll the renegotiation
				// back to the shared previous attempt on BOTH sides: the
				// peer's retained rollback record rolls it back when our
				// abort arrives, and ours rolls back here.
				return this._unwindV2NegotiationOrRollback(derived);
			}
		}
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			...this._driveDualFunding()
		];
	}

	/**
	 * Handle tx_init_rbf from peer (acceptor side).
	 */
	handleTxInitRbf(msg: ITxInitRbfMessage): ChannelAction[] {
		// BOLT 2: on an option_zeroconf channel the peer MUST NOT send
		// tx_init_rbf at all (funding or splice): both sides already treat the
		// unconfirmed lineage as usable, and replacing it creates fund-loss
		// ambiguity. The prescribed response is a warning + disconnect or an
		// error that fails the channel; a mere tx_abort would leave a channel
		// alive whose peer has proven it will try to replace live fundings.
		if (this._isZeroConfChannelType()) {
			return this._failChannelWithWireError(
				'tx_init_rbf is forbidden on an option_zeroconf channel'
			);
		}
		// BOLT 2: the receiver of tx_init_rbf MUST respond with tx_ack_rbf or
		// tx_abort. A splice uses _spliceSession, not a dual-funding session;
		// we do not support RBF of a splice yet, so refuse it properly with
		// tx_abort (the channel itself is unaffected) instead of a generic
		// error the peer cannot interpret.
		if (this._spliceSession && !this._spliceSession.isComplete()) {
			return [
				this._txAbort(
					this._state.channelId ?? msg.channelId,
					'splice RBF not supported'
				)
			];
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}
		// BOLT 2 window: the funding tx may be replaced any time before
		// channel_ready crosses in either direction (the spec's own window is
		// a completed, broadcast, unconfirmed attempt; that is where Eclair
		// and CLN RBF). Superseded broadcastable attempts stay tracked in
		// v2PreviousAttempts until one confirms, so accepting a replacement
		// never orphans a tx that can still appear on chain.
		if (this._state.localChannelReady || this._state.remoteChannelReady) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'cannot RBF a v2 open after channel_ready'
				)
			];
		}
		// A confirmed attempt is final; BOLT 2 forbids replacing it.
		if (this._v2AnyAttemptConfirmed()) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'cannot RBF a v2 open whose funding tx confirmed'
				)
			];
		}
		// Abort and RBF crossed on the wire: our abort is already on its way
		// and the requester's pending-RBF branch will consume it as exactly
		// the refusal this request needs. A SECOND abort here would
		// desynchronize the exchange (the requester answers the first, we
		// tear down on what we take for an echo of the second). Cancel the
		// pending teardown instead: the crossed exchange resolves as a
		// refusal, both sides keep the current attempt, and the operator can
		// re-abort once the wire is quiet. An un-echoed rollback abort of
		// ours refuses the crossed request the same way (its own echo still
		// resolves it; there is no teardown to cancel).
		if (this._v2AbortPending || this._v2RollbackAbortPending) {
			this._v2AbortPending = false;
			return [];
		}
		// A restored (builder-less) session cannot renegotiate: the wallet
		// contribution closures did not survive the restart.
		if (!session.getTxBuilder()) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'cannot RBF a v2 open restored after a restart'
				)
			];
		}
		// RBF replaces a COMPLETED attempt: the recorded one. A tx_init_rbf
		// mid-negotiation is refused (BOLT 2 lets the receiver refuse any),
		// which also guarantees our own asynchronous wallet selection for
		// the attempt has resolved before a replacement can reprice it.
		if (!this._state.v2InFlight) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'no completed funding attempt is recorded to replace'
				)
			];
		}
		// A broadcastable attempt is only replaceable once its commitment
		// exchange completed: the superseded record stays tracked and may
		// confirm, and one without the peer's commitment signature has no
		// unilateral exit. Attempt-scoped refusal (BOLT 2 MAY-abort).
		if (
			this._v2RecordBroadcastable(this._state.v2InFlight) &&
			this._state.v2InFlight.remoteCommitmentSig === null
		) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'cannot RBF before the commitment exchange completes'
				)
			];
		}

		// BOLT 2: "it may be different from the contribution made in the
		// previously completed transaction". An ABSENT TLV means "unchanged"
		// here rather than the spec's "not contributing" (beignet peers
		// predating the TLV send none while keeping their contribution; a spec
		// peer that stops contributing entirely fails the funding-output audit
		// attempt-scoped instead). A changed contribution is accepted within
		// the bounds below, and refusals stay attempt-scoped: both sides keep
		// the recorded attempt.
		const newRemoteContribution =
			msg.fundingOutputContribution ??
			this._state.v2InFlight.remoteContributionSats;
		const localContribution = this._state.v2InFlight.localContributionSats;
		const contributionRefusal = this._v2RbfContributionRefusal(
			localContribution,
			newRemoteContribution
		);
		if (contributionRefusal) {
			return [this._txAbort(this._v2ChannelId(), contributionRefusal)];
		}
		const contributionChanged =
			newRemoteContribution !== this._state.v2InFlight.remoteContributionSats;
		// Honor require_confirmed_inputs: our registered inputs are reused
		// verbatim for the replacement, so a known-unconfirmed one can never
		// satisfy the peer. Mirrors the splice-side check.
		if (
			msg.requireConfirmedInputs &&
			this._dualFundingContribution?.inputs.some((i) => i.confirmed === false)
		) {
			return [
				this._txAbort(
					this._v2ChannelId(),
					'require_confirmed_inputs not satisfied'
				)
			];
		}
		// Refuse a replacement our registered wallet inputs cannot cover at
		// the offered feerate BEFORE the session mutates: the refusal keeps
		// the current attempt intact on both sides (the peer unwinds on the
		// tx_abort), where a post-accept failure would strand an attempt
		// both sides had already agreed to.
		const unaffordable = this._dualFundingAffordabilityError(msg.feerate);
		if (unaffordable) {
			return [
				this._txAbort(this._v2ChannelId(), unaffordable),
				{ type: ChannelActionType.ERROR, message: unaffordable }
			];
		}

		const result = session.handleRbf(
			msg.feerate,
			msg.locktime,
			contributionChanged ? newRemoteContribution : undefined
		);
		if (!result.ok) {
			// Spec-conformant refusal: tx_abort with the reason, plus the
			// app-level error for observability.
			return [
				this._txAbort(
					this._v2ChannelId(),
					result.error || 'Failed to handle RBF'
				),
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle RBF'
				}
			];
		}

		this._state.state = ChannelState.DUAL_FUNDING_V2;
		// The previous attempt's record is RETAINED as rollback state: our
		// ack may never arrive (or the initiator may fail to persist it), in
		// which case the peer still holds the previous attempt and the
		// retained record is the only way back to it. It is replaced only by
		// the NEW attempt's record, in the single commitment persist that
		// makes the replacement durable (_syncV2InFlight); with no separate
		// clear-write to fail, a persistence failure anywhere leaves both
		// sides rolling back to the shared previous attempt. The durable
		// shape DUAL_FUNDING_V2 with a record means exactly "replacement in
		// progress, previous attempt still resumable"; the normal flow
		// cannot produce it (records are created after the state moved to
		// AWAITING_TX_SIGNATURES). Only the driver resets.
		this._resetV2Driver();
		// A changed peer contribution changes the capacity, both balances and
		// the capacity-derived reserve. Applied here, before anything sizes
		// the replacement: our contributions re-derive lazily on the opener's
		// first post-ack tx_add_*, and the funding output, commitment #0 and
		// the completed-tx audits all read these live values.
		if (contributionChanged) {
			this._applyV2ContributionChange(localContribution, newRemoteContribution);
		}
		// Restart our side of the interactive-tx exchange: reprice the
		// registered contribution at the accepted feerate and drop the
		// derived list (stale serial ids from the discarded builder). It
		// re-derives lazily on the opener's first post-ack tx_add_*.
		if (this._dualFundingContribution) {
			this._dualFundingContribution.feeratePerKw = msg.feerate;
			this._dualFundingContribs = null;
			this._dualFundingContribIndex = 0;
		}

		// Send tx_ack_rbf. BOLT 2: a contributor MUST state its
		// funding_output_contribution. Our own share is unchanged by an
		// inbound RBF, so the recorded amount is restated verbatim and a
		// zero-contribution side omits the TLV.
		const ack: ITxAckRbfMessage = { channelId: this._v2ChannelId() };
		const ourContribution = this._state.v2InFlight!.localContributionSats;
		if (ourContribution > 0n) {
			ack.fundingOutputContribution = ourContribution;
		}
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.TX_ACK_RBF, encodeTxAckRbfMessage(ack))
		];
	}

	/**
	 * Abort the dual-funding session.
	 */
	abortDualFunding(reason?: string): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'No dual-funding session to abort'
				}
			];
		}
		// A replacement in progress is attempt-scoped: aborting it returns
		// both sides to the previous attempt, whatever that attempt's
		// signature status. BOLT 2's no-abort-after-tx_signatures rule binds
		// the negotiation whose signatures left; the REPLACEMENT negotiation
		// has signed nothing yet, and tx_abort is its prescribed unwind (the
		// refusal path uses exactly that). Covers both the mid-renegotiation
		// shape (retained rollback record) and a recorded-but-unsigned
		// replacement with superseded attempts behind it.
		const renegotiating =
			(!!this._state.v2InFlight && this._v2RecordIsStaleRollback()) ||
			this._v2ReplacementAbandonable();
		if (!renegotiating) {
			// BOLT 2: a node MUST NOT send tx_abort after transmitting
			// tx_signatures — the peer can complete and broadcast the funding
			// tx.
			if (this._state.v2InFlight?.sentTxSignatures) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'cannot abort a v2 open after tx_signatures were released'
					}
				];
			}
			// A fully signed funding tx is staged for (re)broadcast: the open
			// owes the network a broadcast, not the peer an abort.
			if (this._state.pendingFundingTxHex) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'cannot abort a v2 open whose funding tx is fully signed'
					}
				];
			}
		}
		// Abort and RBF are mutually exclusive, never resolved by arrival
		// order: an un-acked tx_init_rbf of ours is outstanding, and an
		// abort sent behind it would make the peer's answers ambiguous on
		// both sides. Let the request resolve (refusal, ack, or disconnect)
		// first.
		if (this._pendingRbfInit) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot abort while an RBF request is awaiting its answer'
				}
			];
		}
		// A rollback abort of ours (an accepted RBF that failed at ack time)
		// is still awaiting its echo: a second abort behind it would take
		// the delayed echo for its own answer and tear down an attempt the
		// peer rolled back to keep. Let the exchange complete (echo or
		// disconnect) first.
		if (this._v2RollbackAbortPending) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'cannot abort while a rollback tx_abort is awaiting its echo'
				}
			];
		}

		// A RECORDED attempt tears down only when the peer's echo confirms
		// it heard the abort: the peer holds our verified commitment_signed,
		// and if we contributed no inputs it can even complete the funding
		// tx without us. Discarding our state on a lost abort would forget a
		// channel the peer can still act on. Nothing durable changes here;
		// a disconnect forgets the abort and the attempt resumes.
		if (this._state.v2InFlight) {
			this._v2AbortPending = true;
			return [this._txAbort(this._v2ChannelId(), reason)];
		}

		// Pre-commitment: nothing was signed and nothing durable exists, so
		// the negotiation dies immediately, echo or not.
		session.abort();
		this._resetV2Driver();
		this._state.state = ChannelState.ERRORED;
		return [this._txAbort(this._v2ChannelId(), reason)];
	}

	/**
	 * The negotiated v2 funding tx failed its audit: nothing has been signed,
	 * so the open unwinds with a wire tx_abort the peer can act on. A bare
	 * local ERROR here left the peer waiting forever for a commitment_signed
	 * (or a tx_abort) that would never come.
	 */
	private _abortV2Negotiation(reason: string): ChannelAction[] {
		this._state.dualFundingSession?.abort();
		this._resetV2Driver();
		this._state.v2InFlight = null;
		this._state.state = ChannelState.ERRORED;
		return [
			this._txAbort(this._v2ChannelId(), reason),
			{ type: ChannelActionType.ERROR, message: reason }
		];
	}

	/**
	 * Compose a tx_abort send and remember that WE have sent one on this
	 * negotiation. Every tx_abort this channel emits goes through here, so
	 * handleTxAbort can enforce BOLT 2's "having sent one, never answer the
	 * peer's with another" without each send site remembering to mark.
	 */
	private _txAbort(channelId: Buffer, reason?: string): ChannelAction {
		this._txAbortSent = true;
		// The wire format carries the reason in a u16-length field: truncate
		// rather than let the encoder throw after callers already mutated state
		// (the unwind would then be lost along with the send).
		const data = reason
			? Buffer.from(reason, 'utf8').subarray(0, 65535)
			: Buffer.alloc(0);
		return sendMsg(
			MessageType.TX_ABORT,
			encodeTxAbortMessage({ channelId, data })
		);
	}

	/**
	 * Whether this channel is a dead unfunded v2 open: errored with no
	 * funding transaction anyone could ever complete or broadcast. Such a
	 * channel answers nothing forever and is safe to remove entirely (maps
	 * and row); everything it checks is durable, so the answer survives a
	 * restore. Never true once our tx_signatures left (the peer may hold a
	 * broadcastable funding tx), once the fully signed tx was staged for
	 * (re)broadcast, once either channel_ready was exchanged, or once our own
	 * watcher has seen the funding on chain.
	 *
	 * Durable facts only, deliberately. What the record cannot answer is
	 * whether it is CURRENT: a database installed by a recovery restore can
	 * be behind what the node actually did, so callers that would remove a
	 * channel on a purely local inference screen for that separately
	 * (ChannelManager.isChannelRestoredFromDisk).
	 */
	isAbandonedV2Open(): boolean {
		// Chain evidence outranks the record. isV2AttemptBroadcastable answers
		// from what this node remembers doing, and a funding tx our own watcher
		// has seen at depth exists whatever the record says about our
		// witnesses. Removing such a channel would delete the only state that
		// can sweep that funding's outputs, so a confirmed open is never
		// abandoned (issue #463).
		if (this.isFundingKnownOnChain()) return false;
		return (
			this._state.state === ChannelState.ERRORED &&
			this._state.fundingVersion === 2 &&
			!this.isV2AttemptBroadcastable() &&
			!this._state.localChannelReady &&
			!this._state.remoteChannelReady
		);
	}

	/**
	 * The wallet outpoints this side contributed to the v2 open, reported only
	 * when the open is conclusively dead with nothing anyone could broadcast
	 * (isAbandonedV2Open), so callers can release their funding pledges at
	 * once instead of waiting out the pledge TTL (issue #311). The registered
	 * set is the union of every attempt's inputs (an RBF only ever extends it,
	 * to fund a raised contribution), so this covers them all; inputs an
	 * abandoned raise left behind are reported separately by
	 * takeDanglingV2TopUpPledgeOutpoints. Empty for a zero-contribution accept and for channels
	 * restored after a restart (the contribution is process-local; the
	 * provider TTL covers those). txid is display-order hex, matching the
	 * provider's pledge keys.
	 */
	getReleasableV2PledgeOutpoints(): Array<{ txid: string; vout: number }> {
		if (!this.isAbandonedV2Open()) return [];
		const contribution = this._dualFundingContribution;
		if (!contribution) return [];
		try {
			return contribution.inputs.map((input) => ({
				txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
				vout: input.prevOutputIndex
			}));
		} catch {
			return [];
		}
	}

	/**
	 * Whether the PEER may be able to broadcast the recorded funding tx
	 * without any further message from us. True once our witnesses left
	 * (sentTxSignatures) or the fully signed tx exists (fullySigned, or
	 * staged in pendingFundingTxHex), and ALSO for a zero-local-input
	 * attempt: the record only exists once our commitment_signed left, and
	 * a side that contributed no inputs owes no witness bytes, so the peer
	 * can assemble and broadcast the funding tx entirely alone. A
	 * caller-driven attempt whose witnesses are still owed (empty indices
	 * AND empty witnesses) reports broadcastable too: the record cannot
	 * prove otherwise, and every consumer of this answer must fail toward
	 * keeping state. Superseded RBF attempts (v2PreviousAttempts) are
	 * broadcastable by construction, so the channel-wide answer stays true
	 * while any of them is still live.
	 */
	/** Register this channel's record as one loaded from disk at startup. */
	markRecordRestoredFromDisk(): void {
		this._recordRestoredFromDisk = true;
	}

	/** Whether this channel's record was loaded from disk at startup. */
	isRecordRestoredFromDisk(): boolean {
		return this._recordRestoredFromDisk;
	}

	/**
	 * Whether a v2 teardown must RETAIN this open even though the record says
	 * nobody can broadcast its funding tx.
	 *
	 * isV2AttemptBroadcastable answers from what this node remembers doing,
	 * and a restored record cannot prove that: the process that wrote it may
	 * have released tx_signatures afterwards, in which case the peer holds a
	 * complete funding tx and BOLT 2 forbids forgetting the channel until its
	 * inputs are provably unspendable. A peer's tx_abort is honest evidence
	 * that IT wants the open dead, and an honest peer may send one before its
	 * own signatures while already holding ours; neither says the funding is
	 * not on chain. Discarding the open here drops the funding watch, the
	 * monitor spend detection would build from it and the SCB entry, which is
	 * how a peer's force-close went unswept in issue #463. Chain evidence
	 * retires such a channel instead, through the funding-missing watchdog.
	 */
	private v2TeardownMustRetain(): boolean {
		return this._recordRestoredFromDisk;
	}

	isV2AttemptBroadcastable(): boolean {
		if (this._state.pendingFundingTxHex) return true;
		if (this._state.v2PreviousAttempts?.length) return true;
		const rec = this._state.v2InFlight;
		if (!rec) return false;
		return this._v2RecordBroadcastable(rec);
	}

	/**
	 * The per-RECORD broadcastability test behind isV2AttemptBroadcastable,
	 * for callers that ask about one specific attempt rather than the channel
	 * (mid-renegotiation the channel-wide answer stays true for the retained
	 * previous attempts while the CURRENT attempt is still unsigned).
	 */
	private _v2RecordBroadcastable(rec: IV2InFlight): boolean {
		return (
			rec.sentTxSignatures ||
			rec.fullySigned ||
			(rec.ourWalletInputIndices.length === 0 && rec.ourWitnesses.length === 0)
		);
	}

	/**
	 * Whether this channel holds affirmative, persisted, LOCAL evidence that
	 * its funding transaction reached the chain (issue #413). Only our own
	 * watcher's observations count: remoteChannelReady is the peer's claim
	 * (a hostile peer sends channel_ready early, then an error, to make us
	 * broadcast against an outpoint we never saw), and shortChannelId-shaped
	 * values can be peer-supplied on zero-conf paths, so neither is admitted.
	 * The node composes its process-local knowledge (a funding broadcast we
	 * ourselves handed to the backend) at the call site. Like
	 * isV2AttemptBroadcastable, every consumer must fail toward KEEPING
	 * state: "unknown" answers false, and false means skip the commitment
	 * broadcast, never fabricate a close.
	 */
	isFundingKnownOnChain(): boolean {
		const s = this._state;
		// Announcement depth: 6 confs seen by our own watcher while NORMAL.
		if (s.fundingConfirmationHeight > 0) return true;
		// Depth observed by our watcher outside the ready flow (issue #413):
		// after the channel failed, or after the zero-conf fast-track.
		if (s.fundingConfirmedLate === true) return true;
		// v2: confirmation is stamped durably on the attempt records by our
		// own depth callback.
		if (this._v2AnyAttemptConfirmed()) return true;
		// The zero-conf fast-track sets localChannelReady with no chain
		// evidence (the fundingConfirmed short-circuit at funding_signed),
		// so the flag only counts when the ready flow required real depth.
		if (s.zeroConfEnabled && s.trustedPeer) return false;
		// localChannelReady: our own watcher saw minimumDepth.
		return s.localChannelReady;
	}

	/**
	 * The channel state a rolled-back v2 attempt resumes in: an attempt whose
	 * signature exchange completed (or whose witnesses left) is waiting on the
	 * chain again, not on the peer.
	 */
	private _v2StateForRecord(rec: IV2InFlight): ChannelState {
		return rec.sentTxSignatures || rec.fullySigned
			? ChannelState.AWAITING_FUNDING_CONFIRMED
			: ChannelState.AWAITING_TX_SIGNATURES;
	}

	/**
	 * Whether ANY funding attempt of this v2 open has reached depth: the
	 * current record's one-shot confirmation marker, or a superseded
	 * attempt's. BOLT 2 forbids replacing a confirmed funding tx.
	 */
	private _v2AnyAttemptConfirmed(): boolean {
		return !!(
			this._state.v2InFlight?.confirmed ||
			this._state.v2PreviousAttempts?.some((rec) => rec.confirmed)
		);
	}

	/**
	 * Handle tx_abort from peer.
	 */
	handleTxAbort(): ChannelAction[] {
		// Deliberately does NOT clear _spliceAbortIgnoreCommitment: with
		// reentrant synchronous routing the peer's echo can overtake the stray
		// commitment it queued first, and a symmetric refusal delivers the
		// peer's OWN tx_abort with no stray behind it at all (issue 350). The
		// window is resolved by classifying the next commitment_signed itself.
		// The echo/ack of a tx_abort we sent (e.g. telling the peer to forget a
		// splice we lost across a restart). Both sides have now forgotten it.
		if (this._spliceAbortPending) {
			this._spliceAbortPending = false;
			// The echo settles a durably-owed forget: persist the clear, or a
			// restart would keep re-sending tx_abort at every reestablish.
			if (this._state.spliceAbortOwed) {
				this._state.spliceAbortOwed = false;
				return [{ type: ChannelActionType.PERSIST_STATE }];
			}
			return [];
		}

		// An RBF request of ours is outstanding, and abort/RBF are mutually
		// exclusive locally (no abort of ours can be pending behind it), so
		// this abort answers the request: a refusal, or the peer's own
		// operator abort sent before it saw the request, and a peer with a
		// pending abort refuses rather than acks, so either way the request
		// is dead and nothing of the attempt was replaced. Only the request
		// dies; the frozen tx_signatures release of the current attempt
		// resumes. Echo as the ack the abort expects unless an abort of
		// ours is already on the wire (BOLT 2: never answer with a second).
		if (this._pendingRbfInit) {
			// Refused: the raise it proposed never happens, so release the
			// coins selected for it.
			this._releasePendingRbfTopUp();
			this._pendingRbfInit = null;
			if (this._txAbortSent) {
				return this._maybeSendV2TxSigs();
			}
			const actions = [
				this._txAbort(this._v2ChannelId()),
				...this._maybeSendV2TxSigs()
			];
			// The echo terminates this exchange and the channel lives on:
			// reset the latch the compose just set, or the swallow below
			// would eat the peer's NEXT independent abort (issue 337). NOT
			// when the resumed release above just sent our tx_signatures:
			// BOLT 2 forbids tx_abort after transmitting tx_signatures, and
			// the sticky latch is what enforces that from here on.
			if (!this._v2TxSigsReleased) {
				this._txAbortSent = false;
			}
			return actions;
		}

		// The echo of our tx_abort of a RECORDED v2 open: the peer has now
		// confirmed it heard the abort (or crossed us with its own), so both
		// sides are agreed and the deferred teardown runs, durably. Until
		// this moment the attempt stayed fully live, because a lost abort
		// leaves the peer holding our verified commitment_signed. Recheck
		// broadcastability first: witnesses that crossed with the abort can
		// have completed the funding tx in the meantime, and a tx the peer
		// can broadcast must stay tracked even though both sides said abort.
		if (this._txAbortSent && this._v2AbortPending) {
			this._v2AbortPending = false;
			// Mid-renegotiation the record is RETAINED rollback state, and the
			// peer answered our abort by rolling back to it: mirror that
			// instead of tearing down (or keeping the dead renegotiation), or
			// the two sides part with different dispositions of the same
			// attempt. Checked BEFORE the broadcastability keep-arm: in the
			// post-signatures RBF window the retained previous attempt makes
			// the channel-wide broadcastability answer true throughout the
			// renegotiation, and the keep-arm would strand this side in
			// DUAL_FUNDING_V2 while the peer resumed the attempt.
			if (this._state.v2InFlight && this._v2RecordIsStaleRollback()) {
				this._rollbackToRetainedV2Attempt();
				// The exchange is complete both ways (sent and received) and
				// the channel lives on: reset the latch so the peer's next
				// independent abort is answered, not swallowed.
				this._txAbortSent = false;
				return [{ type: ChannelActionType.PERSIST_STATE }];
			}
			// An operator abort of a RECORDED unsigned replacement: the peer
			// answered by resuming the superseded attempt (its own
			// abandonable-replacement arm), so mirror it.
			if (this._v2ReplacementAbandonable()) {
				this._popToPreviousV2Attempt();
				this._txAbortSent = false;
				return [{ type: ChannelActionType.PERSIST_STATE }];
			}
			if (this.isV2AttemptBroadcastable() || this.v2TeardownMustRetain()) {
				// The latch stays SET for the retained attempt: tx_abort has
				// no exchange identifier, so a cleared latch could not tell
				// the peer's next independent abort from a duplicate or an
				// answer to our answer, and answering those would reopen the
				// issue-294 echo loop between two sides that both kept the
				// attempt. The swallow below absorbs further aborts; a
				// disconnect resets the exchange.
				return [];
			}
			this._state.dualFundingSession?.abort();
			this._state.v2InFlight = null;
			this._resetV2Driver();
			this._state.state = ChannelState.ERRORED;
			// Condemned in the same persist: the teardown is decided, and a
			// crash before the manager's handshake cleanup deletes the row
			// must not restore it as a tracked inert channel.
			this._state.condemned = true;
			return [{ type: ChannelActionType.PERSIST_STATE }];
		}

		// We have already sent a tx_abort on this negotiation: this incoming
		// one is the peer's own abort crossing ours, or an answer to an echo
		// of ours the ack-latch above already consumed. BOLT 2: a node that
		// has itself sent tx_abort MUST NOT send another in reply. Answering
		// here is what wedged two honest nodes into an unbounded echo loop
		// after a restart mid-splice (issue 294): the restarted side sends
		// two aborts (the proactive forget and the answer to the peer's
		// next_funding_txid), the one-shot latch absorbs only one ack, and
		// from then on each side saw only "no session, so echo".
		if (this._txAbortSent) {
			// Scope the latch to ONE exchange when a live dual-funding
			// session exists and no abort of ours is still outstanding: this
			// incoming abort is the answer that completes the exchange (e.g.
			// the peer's ack of our refusal echo), and a sticky latch here
			// would silently swallow the NEXT exchange's abort (a second
			// refusal, or a later operator abort). The session-less shape
			// stays sticky: that is the issue-294 restart dance, where more
			// answers than one can arrive.
			if (this._state.dualFundingSession && !this._v2AbortPending) {
				this._txAbortSent = false;
				// The answer to our rollback abort: the peer is back on the
				// shared previous attempt (or crossed us with its own abort,
				// which its retained record resolves the same way), so the
				// frozen tx_signatures release of that attempt resumes.
				if (this._v2RollbackAbortPending) {
					this._v2RollbackAbortPending = false;
					return this._maybeSendV2TxSigs();
				}
			}
			return [];
		}

		// A splice tx_abort unwinds the splice and returns the channel to normal
		// operation (the existing channel is unaffected), rather than erroring it.
		// BOLT 2: a node receiving tx_abort that has not itself sent one MUST
		// echo tx_abort back — the peer treats the echo as the ack that both
		// sides have forgotten the transaction.
		if (this._spliceSession && !this._spliceSession.isComplete()) {
			const hadRecord = !!this._state.spliceInFlight;
			const echo = this._state.channelId
				? [this._txAbort(this._state.channelId)]
				: [];
			const unwind = this.abortSplice('peer sent tx_abort');
			// A record meant the splice was persisted at the commitment round:
			// persist the unwind too (leading, so the echo is bound to the
			// committed state), or a crash would resurrect the aborted splice
			// via restoreSpliceInFlight and the reestablish resume path
			// (issue #356). Skipped when the abort refused and kept the record.
			const persist: ChannelAction[] =
				hadRecord && !this._state.spliceInFlight
					? [{ type: ChannelActionType.PERSIST_STATE }]
					: [];
			return [...persist, ...echo, ...unwind];
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			// Unsolicited tx_abort with nothing in progress (e.g. the peer is
			// discarding a splice we already forgot). BOLT 2: a node that has not
			// itself sent tx_abort MUST echo it back as the ack; it is not a
			// channel failure. The mark set by the echo keeps a peer that
			// answers the answer from starting the same loop remotely.
			if (this._state.channelId) {
				return [this._txAbort(this._state.channelId)];
			}
			return [];
		}

		// A retained rollback record: the peer aborted the renegotiation
		// while the accepted replacement was still unconfirmed by traffic.
		// The previous attempt is the only thing both sides can share; roll
		// back to it (builder-less, restart-equivalent) instead of tearing
		// down, and echo the abort as its ack.
		if (
			this._state.state === ChannelState.DUAL_FUNDING_V2 &&
			this._state.v2InFlight
		) {
			this._rollbackToRetainedV2Attempt();
			const actions: ChannelAction[] = [
				{ type: ChannelActionType.PERSIST_STATE },
				this._txAbort(this._v2ChannelId())
			];
			// The echo terminates this exchange: nothing further is owed or
			// expected on it, and the latch the compose just set would make
			// the swallow above eat the peer's NEXT independent abort (a
			// later operator abort) instead of answering it.
			this._txAbortSent = false;
			return actions;
		}

		// An UNSIGNED replacement the peer has told us to forget: its answer
		// to our next_funding announcement after it rolled the replacement
		// back over a disconnect, or its operator abort of it. Nothing of
		// the replacement can appear on chain (our witnesses never left and
		// the peer cannot complete it alone), so resume the newest
		// superseded attempt and echo the abort as its ack.
		if (this._v2ReplacementAbandonable()) {
			this._popToPreviousV2Attempt();
			const actions: ChannelAction[] = [
				{ type: ChannelActionType.PERSIST_STATE },
				this._txAbort(this._v2ChannelId())
			];
			// The echo terminates this exchange (same rationale as the
			// retained-rollback arm above).
			this._txAbortSent = false;
			return actions;
		}

		// The peer may be able to broadcast the recorded funding tx without
		// us: our witnesses left, or the fully signed tx exists, or we
		// contributed no inputs at all (it needs no bytes from us once our
		// commitment_signed left). BOLT 2: a node MUST NOT forget the
		// channel until the funding's inputs are provably unspendable. Echo
		// the abort as the ack, but keep the record, the state and the
		// watch.
		if (this.isV2AttemptBroadcastable() || this.v2TeardownMustRetain()) {
			// The compose latches _txAbortSent, and for the RETAINED attempt
			// it stays latched: tx_abort has no exchange identifier, so a
			// second inbound abort is indistinguishable from a duplicate or
			// an answer to this echo, and answering it would reopen the
			// issue-294 echo loop between two sides that both kept the
			// attempt. The swallow above absorbs it; a disconnect resets the
			// exchange.
			return [this._txAbort(this._v2ChannelId())];
		}

		session.abort();
		const hadRecord = !!this._state.v2InFlight;
		this._state.v2InFlight = null;
		this._resetV2Driver();
		this._state.state = ChannelState.ERRORED;
		// Condemned in the same persist: the teardown is decided, and a
		// crash between this write and the manager's handshake cleanup
		// deleting the row must not restore it as a tracked inert channel.
		this._state.condemned = true;
		// Echo the tx_abort (BOLT 2 ack) — we had an active session and had not
		// sent tx_abort ourselves. A record meant the open had already been
		// persisted: persist the unwind too, or a restart would resume a round
		// the peer has aborted.
		const actions: ChannelAction[] = hadRecord
			? [{ type: ChannelActionType.PERSIST_STATE }]
			: [];
		actions.push(this._txAbort(this._v2ChannelId()));
		return actions;
	}
}

/**
 * Create a new Channel as the opener.
 */
export function createOpenerChannel(params: {
	fundingSatoshis: bigint;
	pushMsat?: bigint;
	localConfig?: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
}): Channel {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: params.fundingSatoshis,
		pushMsat: params.pushMsat || 0n,
		localConfig: params.localConfig || DEFAULT_CHANNEL_CONFIG,
		localBasepoints: params.localBasepoints,
		localPerCommitmentSeed: params.localPerCommitmentSeed
	});
	return new Channel(state);
}

/**
 * Create a new Channel as the acceptor.
 */
export function createAcceptorChannel(params: {
	temporaryChannelId: Buffer;
	localConfig?: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
}): Channel {
	const state = createAcceptorState({
		temporaryChannelId: params.temporaryChannelId,
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: params.localConfig || DEFAULT_CHANNEL_CONFIG,
		localBasepoints: params.localBasepoints,
		localPerCommitmentSeed: params.localPerCommitmentSeed,
		remoteBasepoints: {
			fundingPubkey: Buffer.alloc(33),
			revocationBasepoint: Buffer.alloc(33),
			paymentBasepoint: Buffer.alloc(33),
			delayedPaymentBasepoint: Buffer.alloc(33),
			htlcBasepoint: Buffer.alloc(33),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		remoteConfig: DEFAULT_CHANNEL_CONFIG
	});
	return new Channel(state);
}
