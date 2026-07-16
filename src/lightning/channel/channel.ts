/**
 * BOLT 2: Channel state machine.
 *
 * Transport-agnostic channel lifecycle management. Every method returns
 * ChannelAction[] arrays; the caller (ChannelManager) maps these to
 * actual transport/broadcast operations.
 */

import crypto from 'crypto';
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
	encodeUpdateAddHtlcMessage,
	IUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage,
	IUpdateFulfillHtlcMessage,
	encodeUpdateFailHtlcMessage,
	IUpdateFailHtlcMessage,
	encodeUpdateFailMalformedHtlcMessage,
	IUpdateFailMalformedHtlcMessage,
	encodeUpdateFeeMessage,
	IUpdateFeeMessage
} from '../message/channel-update';
import {
	encodeCommitmentSignedMessage,
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
import { encodeErrorMessage } from '../message/error';
import {
	ChannelAction,
	ChannelActionType,
	ISendMessageAction
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
	MAX_FUNDING_SATOSHIS
} from './types';
import {
	IChannelState,
	IRemoteForwardingPolicy,
	ISpliceInFlight,
	createOpenerState,
	createAcceptorState
} from './channel-state';
import {
	deriveChannelId,
	deriveV2ChannelId,
	deriveV2TemporaryChannelId,
	validateOpenChannelParams,
	validateAcceptChannelParams,
	isValidShutdownScript
} from './validation';
import { IChannelBasepoints } from '../keys/derivation';
import { FeatureFlags, Feature } from '../features/flags';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import { ChannelSigner, ISigner } from '../keys/signer';
import {
	buildRemoteCommitment,
	signRemoteCommitment,
	verifyRemoteCommitmentSig,
	verifyRemoteCommitmentPartial,
	verifyRemoteHtlcSignatures,
	verifyRemoteHtlcSignaturesTaproot,
	calculateCommitmentFee,
	getCommitmentFeeRate,
	getLocalCommitmentFeeRate,
	HTLC_SUCCESS_WEIGHT
} from './commitment-builder';
import { isAnchorChannel, isTaprootChannel } from './types';
import { generateNonce } from '../crypto/musig';
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
	P2WPKH_DUST_LIMIT,
	SPLICE_TX_BASE_WEIGHT,
	SHARED_FUNDING_INPUT_WEIGHT,
	P2WPKH_INPUT_WEIGHT,
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
	IDualFundingParams
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
	ITxInitRbfMessage
} from '../message/interactive-tx';
import {
	IInteractiveTxInput,
	IInteractiveTxOutput,
	InteractiveTxState
} from '../interactive-tx/types';
import { validateCompletedInteractiveTx } from '../interactive-tx/validation';

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
 * Compute channel reserve: 1% of funding (matching LND/CLN/Eclair),
 * floored at the greater of dust limit and 546 sats (LND's minimum),
 * capped at BOLT 2 max of funding / 5 (20%).
 */
const MIN_CHANNEL_RESERVE_SATOSHIS = 546n; // LND enforces P2PKH dust limit as minimum reserve

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
 * Compute a transaction id (internal byte order, as bitcoinjs addInput expects)
 * from a serialized previous transaction. Used to resolve the prevout txid of an
 * interactive-tx input that arrived with the full prevtx.
 */
function extractTxidFromPrevTx(prevTx: Buffer): Buffer {
	const bitcoin = require('bitcoinjs-lib');
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
		const bitcoin = require('bitcoinjs-lib');
		const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
		const vout = input.prevTxVout ?? input.prevOutputIndex;
		if (vout < 0 || vout >= prev.outs.length) return null;
		return BigInt(prev.outs[vout].value);
	} catch {
		return null;
	}
}

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
	/** Produce the witness stack for this input on the given (unsigned) tx. */
	signWitness: (
		tx: import('bitcoinjs-lib').Transaction,
		inputIndex: number,
		value: bigint
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
	private _spliceSession: SpliceSession | null = null;
	// A splice the caller requested while the channel was not yet quiescent.
	// Fired automatically once we reach QUIESCENT (we drive quiescence ourselves
	// so we become the quiescence initiator, as splice requires).
	private _pendingSplice: {
		relativeSatoshis: bigint;
		fundingFeeratePerkw: number;
		locktime: number;
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
	// then tx_signatures (lower-total-input-sats side first). In-memory only:
	// a disconnect mid-open aborts the v2 open entirely (the manager errors
	// v2 channels on peer disconnect), so nothing here must survive a restart.
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
	// peer's revoke_and_ack acknowledges it. In-memory only: a batch not yet
	// acked is re-sent from here on reconnect.
	private _lastSentBatch: {
		startBatch: Buffer;
		commitments: Buffer[];
	} | null = null;
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
	private _spliceAbortPending = false;
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
		const channelType = channelTypeFlags.toBuffer();
		this._state.channelType = channelType;

		const channelReserve = computeChannelReserve(
			this._state.fundingSatoshis,
			this._state.localConfig.dustLimitSatoshis
		);

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
			// channel"), so force the private flag for taproot.
			channelFlags: preferTaproot ? 0x00 : 0x01,
			channelType
		};

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
		const valid = verifyRemoteCommitmentPartial(
			this._state,
			theirPartial,
			ourPublicNonce,
			theirSigningNonce,
			localPerCommitmentPoint,
			commitmentNumber
		);
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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected accept_channel' }
			];
		}

		if (!msg.temporaryChannelId.equals(this._state.temporaryChannelId)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'temporary_channel_id mismatch'
				}
			];
		}

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
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Invalid accept_channel: ${acceptError}`
				}
			];
		}

		// Store remote config
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

		this._state.minimumDepth = msg.minimumDepth;
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Channel type mismatch in accept_channel'
					}
				];
			}
		}
		if (msg.channelType) {
			this._state.channelType = msg.channelType;
		}

		// option_taproot: record the acceptor's funding nonce. Our own nonce was
		// generated and stored when we sent open_channel.
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.nextLocalNonce || msg.nextLocalNonce.length !== 66) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Taproot accept_channel missing a valid next_local_nonce'
					}
				];
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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected funding_signed' }
			];
		}

		if (this._state.channelId && !msg.channelId.equals(this._state.channelId)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'channel_id mismatch in funding_signed'
				}
			];
		}

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
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
		} else {
			if (this._signer && this._state.remoteBasepoints) {
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
					return [
						{
							type: ChannelActionType.ERROR,
							message: 'Invalid commitment signature in funding_signed'
						}
					];
				}
			}

			// Store remote's commitment signature
			this._state.remoteCommitmentSignature = msg.signature;
		}
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);

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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected open_channel' }
			];
		}

		const error = validateOpenChannelParams(msg, this._maxFundingSatoshis);
		if (error) {
			return [{ type: ChannelActionType.ERROR, message: error }];
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Proposed channel type must include static_remotekey'
					}
				];
			}
			// A zero_conf channel type commits us to minimum_depth 0 (BOLT 2), so
			// only accept it from peers in the trusted set (unconfirmed funding can
			// be double-spent by the opener).
			if (
				proposedFlags.hasFeature(Feature.ZERO_CONF) &&
				!(this._state.zeroConfEnabled && this._state.trustedPeer)
			) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Proposed zero_conf channel type requires a trusted peer'
					}
				];
			}
			this._state.channelType = msg.channelType;
		} else {
			// If no channel type proposed, default to static_remotekey
			const defaultType = FeatureFlags.empty();
			defaultType.setCompulsory(Feature.STATIC_REMOTE_KEY);
			this._state.channelType = defaultType.toBuffer();
		}

		const channelReserve = computeChannelReserve(
			this._state.fundingSatoshis,
			this._state.localConfig.dustLimitSatoshis
		);

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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Taproot open_channel missing a valid next_local_nonce'
					}
				];
			}
			this._state.remoteNonce = msg.nextLocalNonce;
			acceptMsg.nextLocalNonce = this._ensureLocalFundingNonce();
		}

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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected funding_created' }
			];
		}

		if (!msg.temporaryChannelId.equals(this._state.temporaryChannelId)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'temporary_channel_id mismatch'
				}
			];
		}

		this._state.fundingTxid = msg.fundingTxid;
		this._state.fundingOutputIndex = msg.fundingOutputIndex;
		this._state.channelId = deriveChannelId(
			msg.fundingTxid,
			msg.fundingOutputIndex
		);

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
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			if (
				!partialSignatureWithNonce ||
				partialSignatureWithNonce.length !== 98
			) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Taproot funding_signed requires a partial_signature_with_nonce'
					}
				];
			}
		} else {
			if (this._signer && this._state.remoteBasepoints) {
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
					return [
						{
							type: ChannelActionType.ERROR,
							message: 'Invalid commitment signature in funding_created'
						}
					];
				}
			}

			// Store remote's commitment signature
			this._state.remoteCommitmentSignature = msg.signature;
		}
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);

		const signedMsg: IFundingSignedMessage = {
			channelId: this._state.channelId,
			signature: taproot ? Buffer.alloc(64) : signature,
			partialSignatureWithNonce: taproot ? partialSignatureWithNonce : undefined
		};

		this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;

		return [
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
	}

	// ─────────────── Channel Ready ───────────────

	/**
	 * Called when funding transaction reaches minimum depth.
	 * Sends channel_ready.
	 */
	fundingConfirmed(): ChannelAction[] {
		// Funding confirmation only drives action while we are still bringing the
		// channel up. For any later state (NORMAL, closing, reestablish, or already
		// closed) this is stale information — treat it as an idempotent no-op rather
		// than an error so chain-watcher reconciliation on restart stays quiet.
		if (
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY
		) {
			return [];
		}

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
			return [
				sendMsg(MessageType.CHANNEL_READY, encodeChannelReadyMessage(msg)),
				{
					type: ChannelActionType.CHANNEL_READY,
					channelId: this._state.channelId!
				}
			];
		}

		this._state.state = ChannelState.AWAITING_CHANNEL_READY;
		return [sendMsg(MessageType.CHANNEL_READY, encodeChannelReadyMessage(msg))];
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
			return [
				{
					type: ChannelActionType.CHANNEL_READY,
					channelId: this._state.channelId!
				}
			];
		}

		this._state.state = ChannelState.AWAITING_CHANNEL_READY;
		return [];
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
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot add HTLC: channel in ${this._state.state} state`
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

		// Check we have enough balance (including reserve the remote requires us to
		// maintain). When we are the funder we must ALSO be able to pay the
		// commitment fee on top of the reserve (BOLT 2), or the commitment we build
		// would silently clamp our output to 0 / be rejected by the peer. The
		// update_fee path already enforces this; mirror it here for adding HTLCs.
		const reserveMsat = this._state.remoteConfig.channelReserveSatoshis * 1000n;
		let requiredMsat = reserveMsat;
		if (this._state.role === ChannelRole.OPENER) {
			const feeMsat =
				BigInt(
					calculateCommitmentFee(
						this._state.localConfig.feeratePerKw,
						this._countActiveHtlcs() + 1,
						isAnchorChannel(this._state.channelType)
					)
				) * 1000n;
			requiredMsat += feeMsat;
		}
		if (this._state.localBalanceMsat - amountMsat < requiredMsat) {
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

		return [sendMsg(MessageType.UPDATE_ADD_HTLC, payload)];
	}

	/**
	 * Handle update_add_htlc from remote (received HTLC).
	 */
	handleUpdateAddHtlc(msg: IUpdateAddHtlcMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected update_add_htlc' }
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
			return [
				{
					type: ChannelActionType.ERROR,
					message: `update_add_htlc reuses id ${msg.id} with different contents`
				}
			];
		}

		// Reject during quiescence.
		if (this._quiescence.isQuiescing()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_add_htlc: channel is quiescing'
				}
			];
		}

		// Validate inbound HTLC per BOLT 2
		if (msg.amountMsat <= 0n) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'HTLC amount must be greater than 0'
				}
			];
		}

		if (msg.amountMsat < this._state.localConfig.htlcMinimumMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'HTLC amount below our minimum'
				}
			];
		}

		const pendingReceived = this.countPendingHtlcs(HtlcDirection.RECEIVED);
		if (pendingReceived >= this._state.localConfig.maxAcceptedHtlcs) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Max inbound pending HTLCs exceeded'
				}
			];
		}

		const totalReceivedInFlight =
			this.totalInFlightMsat(HtlcDirection.RECEIVED) + msg.amountMsat;
		if (
			totalReceivedInFlight > this._state.localConfig.maxHtlcValueInFlightMsat
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Max inbound HTLC value in flight exceeded'
				}
			];
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
			// the commitment fee above its reserve.
			const feeMsat =
				BigInt(
					calculateCommitmentFee(
						this._state.localConfig.feeratePerKw,
						this._countActiveHtlcs() + 1,
						isAnchorChannel(this._state.channelType)
					)
				) * 1000n;
			remoteRequiredMsat += feeMsat;
		}
		if (this._state.remoteBalanceMsat - msg.amountMsat < remoteRequiredMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Remote cannot afford HTLC above channel reserve'
				}
			];
		}

		// Cap total dust-HTLC exposure (see addHtlc): protects against a peer
		// loading the channel with unenforceable dust that burns to fees on close.
		if (
			this._isDustHtlc(msg.amountMsat) &&
			this._dustExposureMsat() + msg.amountMsat >
				Channel.MAX_DUST_HTLC_EXPOSURE_MSAT
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Dust HTLC exposure limit exceeded'
				}
			];
		}

		// CLTV validation
		if (this._currentBlockHeight > 0) {
			if (msg.cltvExpiry <= this._currentBlockHeight) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'HTLC CLTV already expired'
					}
				];
			}
			if (msg.cltvExpiry > this._currentBlockHeight + 5040) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'HTLC CLTV too far in future'
					}
				];
			}
		}

		const entry: IHtlcEntry = {
			id: msg.id,
			amountMsat: msg.amountMsat,
			paymentHash: msg.paymentHash,
			cltvExpiry: msg.cltvExpiry,
			onionRoutingPacket: msg.onionRoutingPacket,
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.PENDING,
			...(msg.blindingPoint ? { blindingPoint: msg.blindingPoint } : {})
		};

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
	 * Fulfill a received HTLC with a preimage.
	 */
	fulfillHtlc(htlcId: bigint, paymentPreimage: Buffer): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fulfill HTLC: wrong state'
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

		// Verify preimage
		const hash = crypto.createHash('sha256').update(paymentPreimage).digest();
		if (!hash.equals(entry.paymentHash)) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Invalid preimage for HTLC' }
			];
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

		return [sendMsg(MessageType.UPDATE_FULFILL_HTLC, payload)];
	}

	/**
	 * Handle update_fulfill_htlc from remote.
	 */
	handleUpdateFulfillHtlc(msg: IUpdateFulfillHtlcMessage): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN
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
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// Dedup check: a reestablish replay of a fulfill we already processed
		// (BOLT 2 update retransmission) is a no-op.
		if (entry.state === HtlcState.FULFILLED) {
			return [];
		}

		// Verify the revealed preimage actually hashes to this HTLC's
		// payment_hash before crediting the counterparty. Without this a peer
		// could fulfill with a bogus preimage and, on the next revoke_and_ack,
		// move the HTLC value into their balance with no valid proof revealed —
		// direct theft of every HTLC we offer. Mirrors the receive-side check in
		// fulfillHtlc().
		const fulfillHash = crypto
			.createHash('sha256')
			.update(msg.paymentPreimage)
			.digest();
		if (!fulfillHash.equals(entry.paymentHash)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid preimage for offered HTLC'
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
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: wrong state'
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

		return [sendMsg(MessageType.UPDATE_FAIL_HTLC, payload)];
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
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot fail HTLC: wrong state'
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

		return [sendMsg(MessageType.UPDATE_FAIL_MALFORMED_HTLC, payload)];
	}

	/**
	 * Handle update_fail_htlc from remote.
	 */
	handleUpdateFailHtlc(msg: IUpdateFailHtlcMessage): ChannelAction[] {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN
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
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// Dedup check: a reestablish replay of a fail we already processed
		// (BOLT 2 update retransmission) is a no-op.
		if (entry.state === HtlcState.FAILED) {
			return [];
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
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected update_fail_malformed_htlc'
				}
			];
		}

		// BOLT 2: failure_code MUST have BADONION (0x8000) bit set
		if ((msg.failureCode & 0x8000) === 0) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'update_fail_malformed_htlc: failure_code missing BADONION bit'
				}
			];
		}

		const key = `offered-${msg.id}`;
		const entry = this._state.htlcs.get(key);
		if (!entry) {
			return [
				{ type: ChannelActionType.ERROR, message: `HTLC ${msg.id} not found` }
			];
		}

		// Dedup check: a reestablish replay of a fail we already processed is a
		// no-op.
		if (entry.state === HtlcState.FAILED) {
			return [];
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
			return [
				sendMsg(MessageType.START_BATCH, startBatchBytes),
				sendMsg(MessageType.COMMITMENT_SIGNED, currentBytes),
				sendMsg(MessageType.COMMITMENT_SIGNED, spliceBytes)
			];
		}

		return [
			sendMsg(MessageType.COMMITMENT_SIGNED, encodeCommitmentSignedMessage(msg))
		];
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
			// Verify the peer's Schnorr sigs over our second-level HTLC txs FIRST
			// (a pure check, no state writes) — _verifyAndStoreRemotePartial
			// overwrites remoteCommitmentSignature/remoteSigningNonce on success,
			// destroying the CURRENT commitment's force-close witness material.
			// If the HTLC sigs then failed, a later force-close would aggregate
			// the next commitment's partial against the current commitment's tx —
			// an invalid, unminable witness. No state may change unless the whole
			// message verifies.
			if (this._state.remoteBasepoints) {
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
					return [
						{
							type: ChannelActionType.ERROR,
							message: 'Invalid taproot HTLC signature'
						}
					];
				}
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
				return [{ type: ChannelActionType.ERROR, message: err }];
			}
			this._state.remoteHtlcSignatures = msg.htlcSignatures;
		} else {
			// Verify the remote's commitment signature BEFORE revoking old state (Fix 1.1)
			if (this._signer && this._state.remoteBasepoints) {
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
			}

			// Verify HTLC second-level transaction signatures before revoking old state
			if (this._signer && this._state.remoteBasepoints) {
				const htlcPerCommitmentPoint = getPerCommitmentPoint(
					this._state.localPerCommitmentSeed,
					this._state.localCommitmentNumber + 1n
				);
				const htlcSigsValid = verifyRemoteHtlcSignatures(
					this._state,
					this._signer,
					htlcPerCommitmentPoint,
					msg.htlcSignatures
				);
				if (!htlcSigsValid) {
					// BOLT 2: MUST fail the channel (see above).
					return this._failChannelWithWireError('Invalid HTLC signature');
				}
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
			sendMsg(MessageType.REVOKE_AND_ACK, encodeRevokeAndAckMessage(revokeMsg))
		];
	}

	/**
	 * Handle revoke_and_ack from remote.
	 */
	handleRevokeAndAck(msg: IRevokeAndAckMessage): ChannelAction[] {
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Taproot revoke_and_ack missing a valid next_local_nonce'
					}
				];
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

		// Emit HTLC_FORWARDED for committed received HTLCs that haven't been
		// processed yet. This happens AFTER the full commitment round-trip
		// (commitment_signed → revoke_and_ack both ways), ensuring the HTLC
		// is fully committed on both sides before we try to settle it.
		const htlcActions: ChannelAction[] = [];
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.state === HtlcState.COMMITTED &&
				entry.direction === HtlcDirection.RECEIVED
			) {
				htlcActions.push({
					type: ChannelActionType.HTLC_FORWARDED,
					htlcId: entry.id,
					amountMsat: entry.amountMsat,
					paymentHash: entry.paymentHash
				});
			}
		}

		// Persist state after processing revoke_and_ack (Fix 2.2)
		return [{ type: ChannelActionType.PERSIST_STATE }, ...htlcActions];
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

		// Reject a feerate that would drain our (the opener's) balance below reserve,
		// matching the acceptor's reserve guard.
		const activeHtlcCount = this._countActiveHtlcs();
		const anchor = isAnchorChannel(this._state.channelType);
		const newFee = calculateCommitmentFee(
			feeratePerKw,
			activeHtlcCount,
			anchor
		);
		const reserveMsat = this._state.remoteConfig.channelReserveSatoshis * 1000n;
		if (newFee * 1000n > this._state.localBalanceMsat - reserveMsat) {
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

		return [sendMsg(MessageType.UPDATE_FEE, payload)];
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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected update_fee' }
			];
		}

		if (this._state.role !== ChannelRole.ACCEPTOR) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Only opener can send update_fee'
				}
			];
		}

		// Bounds checking: reject unreasonable fee rates
		if (msg.feeratePerKw < 253) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate below minimum relay fee (253 sat/kw)'
				}
			];
		}

		// Absolute ceiling (matches the open_channel validation): even within the
		// 10x relative bound, never accept an absurd feerate that would burn the
		// channel balance as commitment fees.
		if (msg.feeratePerKw > 100_000) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate above absolute maximum (100000 sat/kw)'
				}
			];
		}

		const currentRate = this._state.remoteConfig.feeratePerKw || 253;
		if (msg.feeratePerKw > currentRate * 10) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate unreasonably high (>10x current rate)'
				}
			];
		}

		// Check if new fee rate would drain opener below channel reserve
		const activeHtlcCount = this._countActiveHtlcs();
		const anchor = isAnchorChannel(this._state.channelType);
		const newFee = calculateCommitmentFee(
			msg.feeratePerKw,
			activeHtlcCount,
			anchor
		);
		const reserveMsat = this._state.localConfig.channelReserveSatoshis * 1000n;
		// Remote is the opener (we are acceptor), so check their balance
		if (newFee * 1000n > this._state.remoteBalanceMsat - reserveMsat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Fee rate would drain opener below channel reserve'
				}
			];
		}

		// Dust re-trim guard: on non-anchor channels the trim threshold rises
		// with the feerate, so a fee hike can push previously-untrimmed in-flight
		// HTLCs below dust — silently burning their value into the commitment
		// fee. Reject a feerate that would raise total dust exposure above the
		// same ceiling enforced at HTLC-add time. Rejecting is safe: the ERROR
		// path force-closes at the old committed rate, where the HTLCs are still
		// untrimmed and claimable.
		if (
			this._dustExposureAtRateMsat(msg.feeratePerKw) >
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
		if (
			this._state.state === ChannelState.CLOSED ||
			this._state.state === ChannelState.FORCE_CLOSED
		) {
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
	forceClose(signer: ISigner): ChannelAction[] {
		// Data loss protection: the peer proved our state is stale. Our latest
		// local commitment is revoked in the peer's view - broadcasting it hands
		// our entire balance to the justice path. Recovery is passive: the peer
		// force-closes with its newer commitment and we sweep our to_remote.
		if (this._state.dataLossDetected) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Refusing to broadcast stale commitment after data loss'
				}
			];
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
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot force close: wrong state'
				}
			];
		}

		if (!this._state.fundingTxid || !this._state.remoteBasepoints) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot force close: channel not funded'
				}
			];
		}

		if (!this._state.remoteCommitmentSignature) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot force close: no remote signature'
				}
			];
		}

		// Build our latest local commitment
		const perCommitmentPoint = getPerCommitmentPoint(
			this._state.localPerCommitmentSeed,
			this._state.localCommitmentNumber
		);

		const {
			buildLocalCommitment: buildLocal
		} = require('./commitment-builder');
		const { createFundingScript } = require('../script/funding');

		// Rebuild at the exact feerate the stored remote signature covers
		// (signedLocal=true) — mid-fee-round the in-flight rate can differ,
		// which would change the sighash and make the witness invalid.
		const built = buildLocal(this._state, perCommitmentPoint, undefined, true);

		if (isTaprootChannel(this._state.channelType)) {
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
			// cannot aggregate.
			this._state.localNonce = this._deriveVerificationNonce(
				this._state.localCommitmentNumber
			);
			if (!this._state.remoteSigningNonce) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Cannot force close taproot channel: missing peer signing nonce (remoteSigningNonce) for the current commitment'
					}
				];
			}
			const { aggregateLocalCommitmentSig } = require('./commitment-builder');
			const {
				buildTaprootKeySpendWitness
			} = require('../script/funding-taproot');
			const aggSig = aggregateLocalCommitmentSig(
				this._state,
				signer,
				this._state.localNonce!,
				this._state.remoteSigningNonce,
				this._state.remoteCommitmentSignature,
				perCommitmentPoint,
				this._state.localCommitmentNumber
			);
			built.result.tx.setWitness(0, buildTaprootKeySpendWitness(aggSig));
		} else {
			// Create the funding witness using stored remote signature
			const funding = createFundingScript(
				this._state.localBasepoints.fundingPubkey,
				this._state.remoteBasepoints.fundingPubkey
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
				this._state.remoteCommitmentSignature,
				this._state.localBasepoints.fundingPubkey,
				this._state.remoteBasepoints.fundingPubkey,
				funding.witnessScript
			);

			built.result.tx.setWitness(0, witness);
		}

		this._state.state = ChannelState.FORCE_CLOSED;

		const commitmentTx = built.result.tx.toBuffer();

		return [
			{
				type: ChannelActionType.BROADCAST_TX,
				tx: commitmentTx
			},
			{
				type: ChannelActionType.CHANNEL_CLOSED,
				channelId: this._state.channelId!
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
		// Simple-taproot close: the peer's shutdown MUST carry its MuSig2
		// closing nonce (TLV 8) — without it no closing session can exist and
		// we must never fall back to ECDSA negotiation on a P2TR funding.
		if (isTaprootChannel(this._state.channelType)) {
			if (!msg.shutdownNonce || msg.shutdownNonce.length !== 66) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Taproot shutdown missing the MuSig2 closing nonce (TLV 8)'
					}
				];
			}
		}

		// BOLT 2: reject a shutdown scriptPubkey that is not a standard spendable
		// form. Without this, a buggy/malicious peer could strand the cooperative
		// close output in an unspendable script. We accept any valid witness
		// program (incl. P2TR) so taproot peers can coop-close cleanly. OP_RETURN
		// forms are additionally allowed under option_simple_close (dust burn).
		if (
			!isValidShutdownScript(
				msg.scriptPubkey,
				true,
				this._state.simpleClose === true
			)
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Invalid shutdown scriptPubkey'
				}
			];
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

		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN
		) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected shutdown' }
			];
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
		// Stay in the current state (channel + funding watch intact) and error.
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
		// Verify the peer's closing signature over the agreed tx FIRST; on failure stay
		// in NEGOTIATING_CLOSING (channel + funding watch intact). The callback is
		// optional so existing unit callers that only exercise fee logic are unaffected.
		const peerSigValid = (feeSatoshis: bigint): boolean =>
			!verifyClosingFn || verifyClosingFn(feeSatoshis, msg.signature);

		// If their fee matches our last proposal → agreement reached
		if (
			this._state.lastProposedClosingFeeSat !== null &&
			msg.feeSatoshis === this._state.lastProposedClosingFeeSat
		) {
			if (!peerSigValid(msg.feeSatoshis)) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Coop-close: peer closing signature failed to verify'
					}
				];
			}
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
			if (!peerSigValid(msg.feeSatoshis)) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Coop-close: peer closing signature failed to verify'
					}
				];
			}
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
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Taproot closing_signed missing the MuSig2 partial signature (TLV 6)'
				}
			];
		}
		if (!this._remoteClosingNonce || !this._ourClosingNonce) {
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
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							`Taproot closing fee must echo our offer: sent ${this._state.lastProposedClosingFeeSat}, ` +
							`got ${msg.feeSatoshis}`
					}
				];
			}
			if (!peerSigValid(msg.feeSatoshis)) {
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'Coop-close: peer closing partial signature failed to verify'
					}
				];
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: `Taproot closing fee ${msg.feeSatoshis} leaves our output below dust (balance ${openerBalanceSat}, dust ${dust})`
					}
				];
			}
		} else if (msg.feeSatoshis > openerBalanceSat) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Taproot closing fee ${msg.feeSatoshis} exceeds opener balance ${openerBalanceSat}`
				}
			];
		}
		if (!peerSigValid(msg.feeSatoshis)) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Coop-close: peer closing partial signature failed to verify'
				}
			];
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

	private calculateIdealClosingFee(): bigint {
		const feeRate = this._state.localConfig.feeratePerKw || 253;
		// Taproot single-round close: the responder accepts our fee verbatim, so
		// it must make the tx actually relayable. Use the SAME weight model as
		// the tx builder (chain/closing.ts) with the 66-WU key-spend witness.
		if (isTaprootChannel(this._state.channelType)) {
			const localLen = this._state.localShutdownScript?.length ?? 22;
			const remoteLen = this._state.remoteShutdownScript?.length ?? 22;
			return calculateClosingFee(feeRate, localLen, remoteLen, true);
		}
		// A typical closing tx is ~170 weight units (simplified calculation)
		// fee = weight * feeratePerKw / 1000
		const weight = 170;
		return BigInt(Math.ceil((weight * feeRate) / 1000));
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
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;
		this._state.state = ChannelState.ERRORED;
		return true;
	}

	markForReestablish(): void {
		if (
			this._state.state !== ChannelState.NORMAL &&
			this._state.state !== ChannelState.SHUTTING_DOWN &&
			this._state.state !== ChannelState.NEGOTIATING_CLOSING &&
			this._state.state !== ChannelState.AWAITING_CHANNEL_READY &&
			this._state.state !== ChannelState.AWAITING_FUNDING_CONFIRMED &&
			this._state.state !== ChannelState.SPLICING
		) {
			return; // Only mark operational or funded channels
		}

		// A disconnect aborts any quiescence handshake, so a splice we were waiting
		// to start can never fire. Drop it rather than leave it dangling.
		this._pendingSplice = null;

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
		// survives a disconnect.
		this._spliceAbortPending = false;
		this._reestablishRetransmitted = false;

		// Quiescence never survives a disconnect (BOLT 2 quiescence).
		this._quiescence.reset();
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
		// opposite case: they stay and replay via pendingLocalUpdates.)
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
	}

	/**
	 * BOLT 1 "fail the channel" for a peer protocol violation: send a wire
	 * error scoped to this channel (a conformant peer force-closes and stops
	 * using it), mark the channel ERRORED so no further updates are exchanged
	 * over provably-desynced state, persist FIRST, and surface the app-level
	 * error. Generalizes the DLP fell-behind pattern in handleReestablish.
	 *
	 * ONLY for violations by the PEER (invalid signatures, bad revocation
	 * secrets, ...): a wire error kills the channel at the peer, so local API
	 * misuse must keep returning plain ERROR actions.
	 */
	private _failChannelWithWireError(message: string): ChannelAction[] {
		this._state.state = ChannelState.ERRORED;
		const channelId = this._state.channelId ?? this._state.temporaryChannelId;
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(
				MessageType.ERROR,
				encodeErrorMessage({
					channelId,
					data: Buffer.from(message, 'ascii')
				})
			),
			{ type: ChannelActionType.ERROR, message }
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

		const actions: ChannelAction[] = [];

		// We dropped an unresumable splice; the peer may still hold it in-flight.
		// The tx_abort must go out BEFORE our channel_reestablish: CLN's channeld
		// runs every message it reads while waiting for our reestablish through
		// its tx_abort check, but once it has processed our reestablish it resumes
		// the splice and hard-errors when the splice commitment doesn't follow.
		// Sent once — on receipt CLN deletes the inflight, acks with its own
		// tx_abort and restarts channeld on the SAME connection, which then sends
		// a fresh channel_reestablish (handled as a re-reestablish upstream).
		if (this._forgottenSplice && this._state.channelId) {
			this._forgottenSplice = false;
			this._spliceAbortPending = true;
			actions.push(
				sendMsg(
					MessageType.TX_ABORT,
					encodeTxAbortMessage({
						channelId: this._state.channelId,
						data: Buffer.from('splice not resumable after disconnect', 'utf8')
					})
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
					sendMsg(
						MessageType.TX_ABORT,
						encodeTxAbortMessage({
							channelId: this._state.channelId,
							data: Buffer.from('unknown next_funding_txid', 'utf8')
						})
					)
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
			const abortActions = this.abortSplice(
				'peer reestablished without next_funding_txid'
			);
			actions.push(
				...abortActions.filter((a) => a.type !== ChannelActionType.ERROR)
			);
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

		const bitcoinLib = require('bitcoinjs-lib');
		const tx = bitcoinLib.Transaction.fromHex(inflight.spliceTxHex);

		const { createFundingScript } = require('../script/funding');
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
			this._state.state = ChannelState.ERRORED;
			return [
				// Persist FIRST: a crash between the error send and the peer's
				// force-close must not forget that broadcasting is forbidden.
				{ type: ChannelActionType.PERSIST_STATE },
				sendMsg(
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

		// ── Commitment retransmission logic ──
		// msg.nextCommitmentNumber is the next commitment the peer expects to RECEIVE from us.
		// We've created up to remoteCommitmentNumber commitments for them.
		if (msg.nextCommitmentNumber > this._state.remoteCommitmentNumber + 1n) {
			// Peer expects a commitment we've never created — irrecoverable gap
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Remote expects future commitment we have not created'
				}
			];
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
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Remote expects future revocation we have not sent'
				}
			];
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
				revokeRetransmit.push(
					sendMsg(
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
		const pendingLock = this.isSplicePendingLock();

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
				actions.push(sendMsg(update.type as MessageType, update.payload));
			}
		}

		// ── Retransmit our pending-lock commitment BATCH if the peer missed it ──
		// The generic single-message path below can't: it holds neither the
		// start_batch framing nor the splice-side commitment. Replay the cached
		// wire bytes verbatim (idempotent — same signatures, no nonce reuse).
		if (
			pendingLock &&
			this._lastSentBatch &&
			msg.nextCommitmentNumber <= this._state.remoteCommitmentNumber &&
			this._state.remoteCommitmentNumber > 0n
		) {
			actions.push(
				sendMsg(MessageType.START_BATCH, this._lastSentBatch.startBatch)
			);
			for (const c of this._lastSentBatch.commitments) {
				actions.push(sendMsg(MessageType.COMMITMENT_SIGNED, c));
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
					sendMsg(
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

		// ── Splice resumption (merged splice spec) ──
		actions.push(...this._handleReestablishSplice(msg));

		// ── Retransmit channel_ready if we sent it previously (BOLT 2 §5) ──
		// Per spec: on reconnection, if a node sent channel_ready, it MUST retransmit it.
		if (
			this._state.localChannelReady &&
			(this._state.state === ChannelState.AWAITING_CHANNEL_READY ||
				this._state.state === ChannelState.AWAITING_FUNDING_CONFIRMED)
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
				sendMsg(MessageType.CHANNEL_READY, encodeChannelReadyMessage(readyMsg))
			);
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
	handleStfuMessage(_msg: IStfuMessage): ChannelAction[] {
		if (this._state.state !== ChannelState.NORMAL) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected STFU: channel not in NORMAL state'
				}
			];
		}

		// Check for pending HTLCs
		if (this.hasPendingHtlcs()) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot accept STFU: pending HTLCs exist'
				}
			];
		}

		const result = this._quiescence.handlePeerStfu();
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
			actions.push(
				...this._startSplice(
					pending.relativeSatoshis,
					pending.fundingFeeratePerkw,
					pending.locktime
				)
			);
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
		}

		// Already quiescent — start the splice immediately.
		if (this._quiescence.isQuiescent()) {
			return this._startSplice(relativeSatoshis, fundingFeeratePerkw, locktime);
		}

		// Not quiescent yet: remember the request and drive quiescence ourselves
		// so we become the quiescence initiator (the side allowed to send
		// splice_init). The deferred splice fires from handleStfuMessage once we
		// reach QUIESCENT.
		this._pendingSplice = { relativeSatoshis, fundingFeeratePerkw, locktime };

		if (this._quiescence.isQuiescing()) {
			// STFU already in flight; just wait for QUIESCENT.
			return [];
		}

		const stfuActions = this.initiateQuiescence();
		// If quiescence couldn't be started (e.g. pending HTLCs), surface the
		// error and drop the pending splice rather than leaving it dangling.
		if (stfuActions.some((a) => a.type === ChannelActionType.ERROR)) {
			this._pendingSplice = null;
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

		this._spliceSession = new SpliceSession(params);
		const result = this._spliceSession.initiate();

		if (!result.ok) {
			this._spliceSession = null;
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		this._state.preSpliceState = this._state.state;
		this._state.state = ChannelState.SPLICING;

		const spliceMsg = result.message as ISpliceMessage;
		return [sendMsg(MessageType.SPLICE, encodeSpliceMessage(spliceMsg))];
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

		if (!this._state.channelId) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Cannot accept splice: no channel ID'
				}
			];
		}

		const params: ISpliceSessionParams = {
			channelId: this._state.channelId,
			localFundingPubkey: this._state.localBasepoints.fundingPubkey,
			isInitiator: false,
			localRelativeSatoshis,
			fundingFeeratePerkw: msg.fundingFeeratePerkw,
			locktime: msg.locktime
		};

		this._spliceSession = new SpliceSession(params);
		const result = this._spliceSession.handleSplice(msg);

		if (!result.ok) {
			this._spliceSession = null;
			return [{ type: ChannelActionType.ERROR, message: result.error! }];
		}

		// The combined contributions must not grow the channel past the funding
		// cap (2^24 sat, lifted only when option_wumbo was negotiated).
		const postSpliceCapacity =
			this._state.fundingSatoshis + this._spliceSession.getNetCapacityChange();
		if (postSpliceCapacity > this._maxFundingSatoshis) {
			this._spliceSession = null;
			return [
				{
					type: ChannelActionType.ERROR,
					message: `Cannot accept splice: post-splice capacity ${postSpliceCapacity} exceeds maximum ${this._maxFundingSatoshis}`
				}
			];
		}

		this._state.preSpliceState = this._state.state;
		this._state.state = ChannelState.SPLICING;

		const ackMsg = result.message as ISpliceAckMessage;
		return [sendMsg(MessageType.SPLICE_ACK, encodeSpliceAckMessage(ackMsg))];
	}

	/**
	 * Handle splice_ack from remote (initiator side).
	 */
	handleSpliceAck(msg: ISpliceAckMessage): ChannelAction[] {
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
				sendMsg(
					MessageType.TX_ABORT,
					encodeTxAbortMessage({
						channelId: this._state.channelId!,
						data: Buffer.from('post-splice capacity exceeds maximum', 'utf8')
					})
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
				sendMsg(
					MessageType.TX_ABORT,
					encodeTxAbortMessage({
						channelId: this._state.channelId!,
						data: Buffer.from('require_confirmed_inputs not satisfied', 'utf8')
					})
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

		const { createFundingScript } = require('../script/funding');
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

			// Drop a dust change output (the dust implicitly becomes extra fee) —
			// a sub-dust output would make the splice tx nonstandard.
			const changeSats = walletTotal - netChange - feeSats;
			if (changeSats > P2WPKH_DUST_LIMIT) {
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
		const { createFundingScript } = require('../script/funding');
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
		// send them in tx_signatures.
		const ourWalletWitnesses: Buffer[][] = [];
		const ourWalletInputIndices: number[] = [];
		if (this._spliceInInputs) {
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
				const witness = w.signWitness(tx, i, w.value);
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

		// Apply the peer's wallet-input witnesses to the non-shared inputs we did
		// not sign ourselves (in ascending input order).
		if (peerWalletWitnesses.length > 0) {
			const ours = new Set(ourWalletInputIndices);
			let w = 0;
			for (
				let i = 0;
				i < tx.ins.length && w < peerWalletWitnesses.length;
				i++
			) {
				if (i === sharedInputIndex || ours.has(i)) continue;
				tx.setWitness(i, peerWalletWitnesses[w++]);
			}
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
		actions.push(
			sendMsg(MessageType.SPLICE_LOCKED, encodeSpliceLockedMessage(lockedMsg))
		);

		// If both sides have sent splice_locked, the splice is complete
		if (this._spliceSession.isComplete()) {
			this.completeSplice();
			actions.push({ type: ChannelActionType.SPLICE_COMPLETE });
		}
		actions.push({ type: ChannelActionType.PERSIST_STATE });

		return actions;
	}

	/**
	 * Abort a splice operation.
	 */
	abortSplice(reason?: string): ChannelAction[] {
		if (!this._spliceSession) {
			// A splice may have been requested but is still waiting for quiescence
			// (no session created yet). Cancelling that is a no-op success.
			if (this._pendingSplice) {
				this._pendingSplice = null;
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
	}

	/**
	 * A shallow copy of the channel state re-anchored on the spliced funding
	 * output (new outpoint, capacity and balances), used to build/verify the new
	 * commitment during the mid-splice commitment round WITHOUT mutating the live
	 * state (the old commitment must stay valid until splice_locked).
	 */
	private _splicedState(): IChannelState | null {
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
			this._state.fundingSatoshis +
			session.getNetCapacityChange() -
			newCapacity;
		const myFeeMsat = session.isInitiator() ? feeFromChannelSats * 1000n : 0n;
		const myNewLocalMsat =
			this._state.localBalanceMsat +
			session.getLocalRelativeSatoshis() * 1000n -
			myFeeMsat;
		const theirNewMsat = newCapacity * 1000n - myNewLocalMsat;

		// The spliced commitment spends the NEW funding 2-of-2, which uses the
		// funding pubkeys negotiated in splice_init/splice_ack — NOT necessarily
		// the original channel funding pubkeys. CLN derives a fresh funding pubkey
		// per splice; beignet reuses its own. Override the funding pubkeys (only)
		// so the commitment's funding witness script and anchor outputs match what
		// the peer signed. All other basepoints (revocation/payment/delayed/htlc)
		// are unchanged by a splice.
		const splicedRemoteBasepoints = this._state.remoteBasepoints
			? {
					...this._state.remoteBasepoints,
					fundingPubkey:
						session.getRemoteFundingPubkey() ??
						this._state.remoteBasepoints.fundingPubkey
			  }
			: this._state.remoteBasepoints;
		const splicedLocalBasepoints = {
			...this._state.localBasepoints,
			fundingPubkey: session.getLocalFundingPubkey()
		};

		return {
			...this._state,
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
		if (!this.isSplicePendingLock()) {
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
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Commitment batch without a pending splice'
				}
			];
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
		// HTLC traffic is rejected during the pending-lock window (splices begin
		// quiescent, i.e. with no HTLCs, and new adds are refused until the
		// splice locks), so both commitments are HTLC-free here. Reject a peer
		// that nonetheless attaches HTLC sigs to a splice commitment.
		if (spliceMsg.htlcSignatures.length > 0) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Unexpected HTLC signatures in a pending-lock batch'
				}
			];
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
			this._syncSpliceInFlight({
				remoteCommitmentSig: this._spliceRemoteCommitmentSig,
				remoteCommitmentSigFeeratePerKw: spliceSigFeeratePerKw
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

		if (this._signer && this._state.remoteBasepoints) {
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
		}
		this._spliceRemoteCommitmentSig = Buffer.from(msg.signature);
		this._spliceReceivedCommitment = true;
		// Keep the persisted in-flight record in sync (it may already exist from
		// our own commitment send): the peer's commitment sig must survive a
		// crash, and reestablish derives retransmit_flags from it.
		if (this._state.spliceInFlight) {
			this._syncSpliceInFlight({
				remoteCommitmentSig: this._spliceRemoteCommitmentSig
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

		// Our shared-input (2-of-2 funding) signature travels in the
		// shared_input_signature TLV; witnesses carry only the stacks for the
		// wallet inputs we contributed (splice-in), in tx-input order.
		const msg: ITxSignaturesMessage = {
			channelId: this._state.channelId,
			txid: signed.spliceTxid,
			witnesses: this._spliceTx!.ourWalletWitnesses,
			sharedInputSignature: signed.signature
		};
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.TX_SIGNATURES, encodeTxSignaturesMessage(msg))
		];
	}

	/**
	 * Complete the splice: update channel funding outpoint, balances, and exit quiescence.
	 */
	private completeSplice(): void {
		if (!this._spliceSession) return;

		// Capture the fee-adjusted new outpoint/capacity/balances from the actual
		// splice transaction before the driver is reset.
		const spliced = this._splicedState();
		const txid = this._spliceSession.getSpliceTxid();
		const outputIndex = this._spliceSession.getSpliceFundingOutputIndex();

		if (spliced) {
			this._state.spliceFundingTxid = txid;
			this._state.spliceFundingOutputIndex = spliced.fundingOutputIndex;
			this._state.fundingTxid = spliced.fundingTxid;
			this._state.fundingOutputIndex = spliced.fundingOutputIndex;
			this._state.fundingSatoshis = spliced.fundingSatoshis;
			this._state.localBalanceMsat = spliced.localBalanceMsat;
			this._state.remoteBalanceMsat = spliced.remoteBalanceMsat;
			// Adopt the splice-negotiated funding pubkeys: post-splice commitments
			// spend the new funding 2-of-2 and must use these, not the originals.
			this._state.localBasepoints = spliced.localBasepoints;
			this._state.remoteBasepoints = spliced.remoteBasepoints;
		} else if (txid) {
			// Fallback: net-change accounting (does not subtract the on-chain fee).
			this._state.spliceFundingTxid = txid;
			this._state.spliceFundingOutputIndex = outputIndex;
			this._state.fundingTxid = txid;
			this._state.fundingOutputIndex = outputIndex;
			this._state.fundingSatoshis += this._spliceSession.getNetCapacityChange();
			this._state.localBalanceMsat +=
				this._spliceSession.getLocalRelativeSatoshis() * 1000n;
			this._state.remoteBalanceMsat +=
				this._spliceSession.getRemoteRelativeSatoshis() * 1000n;
		}

		// Adopt the peer's signature on our NEW commitment (exchanged during the
		// mid-splice commitment_signed round) so we can unilaterally close the
		// spliced channel. If for some reason no mid-splice commitment was
		// exchanged, fall back to driving a post-splice commitment round.
		if (this._spliceRemoteCommitmentSig) {
			this._state.remoteCommitmentSignature = this._spliceRemoteCommitmentSig;
			// The splice window is HTLC-free (splices start quiescent and new
			// HTLCs are refused until the lock), so the post-splice commitment
			// carries no HTLC outputs.
			this._state.remoteHtlcSignatures = [];
			// Rebuild at the rate the adopted signature was actually made at, not
			// a feerate that may have been staged (update_fee) but not yet signed.
			this._state.lastSignedCommitFeeratePerKw =
				this._state.spliceInFlight?.remoteCommitmentSigFeeratePerKw ??
				getLocalCommitmentFeeRate(this._state);
		} else {
			this._state.needsCommitment = true;
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
		this._state.announcementSigsSent = false;
		this._state.announcementSigsReceived = false;
		this._state.localAnnouncementNodeSig = null;
		this._state.localAnnouncementBitcoinSig = null;
		this._state.remoteAnnouncementNodeSig = null;
		this._state.remoteAnnouncementBitcoinSig = null;
		this._state.fundingConfirmationHeight = 0;
		this._state.fundingTxIndex = 0;

		// Exit quiescence and restore normal operation
		this._quiescence.exitQuiescence();
		this._state.quiescenceState = QuiescenceState.NORMAL;
		this._state.quiescenceInitiator = false;
		this._state.state = ChannelState.NORMAL;
		this._state.preSpliceState = null;
		this._state.spliceInFlight = null;

		this._spliceSession = null;
		this._resetSpliceDriver();
	}

	private hasPendingHtlcs(): boolean {
		for (const entry of this._state.htlcs.values()) {
			if (
				entry.state === HtlcState.PENDING ||
				entry.state === HtlcState.COMMITTED
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
		const { encodeShortChannelId } = require('../gossip/types');
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
		const {
			encodeAnnouncementSignaturesMessage
		} = require('../gossip/messages');
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
		const ecc = require('@bitcoinerlab/secp256k1');
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
			BITCOIN_CHAIN_HASH,
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
		const { encodeChannelAnnouncementMessage } = require('../gossip/messages');
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
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: this._state.shortChannelId!,
			nodeId1: isNode1 ? localNodeId : remoteNodeId,
			nodeId2: isNode1 ? remoteNodeId : localNodeId,
			bitcoinKey1: isNode1 ? localBp.fundingPubkey : remoteBp.fundingPubkey,
			bitcoinKey2: isNode1 ? remoteBp.fundingPubkey : localBp.fundingPubkey
		});

		// Build initial channel_update (direction = our direction bit)
		const { encodeChannelUpdateMessage } = require('../gossip/messages');
		const directionBit = isNode1 ? 0 : 1;
		// BOLT 7: htlc_maximum_msat MUST be <= channel capacity
		const capacityMsat = this._state.fundingSatoshis * 1000n;
		const htlcMaxMsat =
			this._state.localConfig.maxHtlcValueInFlightMsat > capacityMsat
				? capacityMsat
				: this._state.localConfig.maxHtlcValueInFlightMsat;

		const channelUpdate = encodeChannelUpdateMessage({
			signature: Buffer.alloc(64), // placeholder — caller should sign
			chainHash: BITCOIN_CHAIN_HASH,
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
		if (params.channelType) {
			this._state.channelType = Buffer.from(params.channelType);
		} else {
			const defaultType = FeatureFlags.empty();
			defaultType.setCompulsory(Feature.STATIC_REMOTE_KEY);
			this._state.channelType = defaultType.toBuffer();
		}

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
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected open_channel2' }
			];
		}

		this._state.fundingVersion = 2;
		this._state.commitmentFeeratePerkw = msg.commitmentFeeratePerkw;
		this._state.fundingLocktime = msg.locktime;

		// Same trusted-peer gate as the v1 path: a zero_conf channel type commits
		// us to minimum_depth 0, which we only extend to trusted peers.
		if (msg.channelType) {
			const proposedFlags = FeatureFlags.fromBuffer(msg.channelType);
			if (
				proposedFlags.hasFeature(Feature.ZERO_CONF) &&
				!(this._state.zeroConfEnabled && this._state.trustedPeer)
			) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Proposed zero_conf channel type requires a trusted peer'
					}
				];
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
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle open_channel2'
				}
			];
		}

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
		// Record the negotiated channel type (session validated any mismatch) so
		// commitment #0 is built with the same anchor/taproot dispatch on both
		// sides. Default per BOLT 2: static_remotekey.
		if (msg.channelType) {
			this._state.channelType = Buffer.from(msg.channelType);
		} else {
			const defaultType = FeatureFlags.empty();
			defaultType.setCompulsory(Feature.STATIC_REMOTE_KEY);
			this._state.channelType = defaultType.toBuffer();
		}
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
		// (computed, and it does not affect commitment bytes).
		this._state.remoteConfig = {
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: computeChannelReserve(
				this._state.fundingSatoshis,
				msg.dustLimitSatoshis
			),
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: msg.commitmentFeeratePerkw
		};

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
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Script-enforced lease is not supported on taproot channels'
				}
			];
		}

		// Likewise anchors-only: the plain P2WPKH to_remote of a non-anchor
		// channel cannot carry the lease CLTV, so the lessor's balance on the
		// buyer's commitment would be unencumbered (the S-L.H4 escape).
		if (
			!isAnchorChannel(msg.channelType ?? null) &&
			localParams.willFund &&
			msg.requestFunds
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Script-enforced lease requires an anchor channel (option_anchors channel_type)'
				}
			];
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: `Buyer lease blockheight ${bh} is out of the acceptable range`
					}
				];
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
			if (feeMsat > this._state.remoteBalanceMsat) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Buyer balance cannot cover the lease fee'
					}
				];
			}
			this._state.localBalanceMsat += feeMsat;
			this._state.remoteBalanceMsat -= feeMsat;
			// We are the lessor: our to_local is CSV-locked until the lease expires.
			this._state.leaseExpiry = computeLeaseExpiry(
				msg.requestFunds.blockheight
			);
			this._state.isLessor = true;
			// Remember the routing-fee caps we signed: while the lease is active we
			// MUST NOT advertise a channel_update exceeding them (the buyer paid
			// for capped fees).
			this._state.leaseChannelFeeMaxBaseMsat =
				localParams.willFund.leaseRates.channelFeeMaxBaseMsat;
			this._state.leaseChannelFeeMaxProportionalThousandths =
				localParams.willFund.leaseRates.channelFeeMaxProportionalThousandths;
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
		if (this._state.state !== ChannelState.DUAL_FUNDING_V2) {
			return [
				{ type: ChannelActionType.ERROR, message: 'Unexpected accept_channel2' }
			];
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}

		const result = session.handleAcceptChannel2(msg);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle accept_channel2'
				}
			];
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
		// own commitment feerate (which we build both commitments at).
		this._state.remoteConfig = {
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: computeChannelReserve(
				this._state.fundingSatoshis,
				msg.dustLimitSatoshis
			),
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			feeratePerKw: this._state.commitmentFeeratePerkw
		};

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
			return [
				{
					type: ChannelActionType.ERROR,
					message: 'Script-enforced lease is not supported on taproot channels'
				}
			];
		}
		// Anchors-only for the same reason as handleOpenChannel2: a non-anchor
		// P2WPKH to_remote cannot carry the lessor's lease CLTV.
		if (
			!isAnchorChannel(session.getOpenChannelType() ?? null) &&
			msg.willFund &&
			requestFunds
		) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'Script-enforced lease requires an anchor channel (option_anchors channel_type)'
				}
			];
		}
		if (msg.willFund && requestFunds) {
			// M2 fund-safety: the seller must actually contribute at least the inbound
			// liquidity we are paying the lease fee for. verifyWillFund authenticates
			// the seller's signature but does NOT bind the funded amount, so without
			// this check an adversarial seller could return fundingSatoshis=0, pocket
			// the lease fee, and deliver no liquidity — an unconditional loss to us.
			if (msg.fundingSatoshis < requestFunds.requestedSats) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Seller funded less than the requested lease amount'
					}
				];
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
				return [
					{
						type: ChannelActionType.ERROR,
						message:
							'No maximum lease rates configured; refusing to pay an unverified lease fee'
					}
				];
			}
			const maxLeaseFeeSat = computeLeaseFeeSat(
				maxLeaseRates,
				leasedSats,
				fundingFeeratePerkw
			);
			if (leaseFeeSat > maxLeaseFeeSat) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Seller lease fee exceeds our accepted maximum'
					}
				];
			}
			const feeMsat = leaseFeeSat * 1000n;
			if (feeMsat > this._state.localBalanceMsat) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Cannot cover the lease fee from our balance'
					}
				];
			}
			this._state.localBalanceMsat -= feeMsat;
			this._state.remoteBalanceMsat += feeMsat;
			this._state.leaseExpiry = computeLeaseExpiry(requestFunds.blockheight);
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
						sendMsg(
							MessageType.TX_ABORT,
							encodeTxAbortMessage({
								channelId: this._state.channelId!,
								data: Buffer.from(
									'splice shared input does not match the channel funding outpoint',
									'utf8'
								)
							})
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
					sendMsg(
						MessageType.TX_ABORT,
						encodeTxAbortMessage({
							channelId: this._state.channelId!,
							data: Buffer.from(err, 'utf8')
						})
					),
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

		return [];
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

		return [];
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
			const invalid = this._validateNegotiatedInteractiveTx('v2');
			if (invalid) {
				return [{ type: ChannelActionType.ERROR, message: invalid }];
			}
			this._state.state = ChannelState.AWAITING_TX_SIGNATURES;
		}

		// BOLT 2 v2: once both sides have completed, the commitment_signed
		// exchange starts (before any tx_signatures). Ours goes out right after
		// our tx_complete on the wire.
		return [
			sendMsg(
				MessageType.TX_COMPLETE,
				encodeTxCompleteMessage({
					channelId: this._v2ChannelId()
				})
			),
			...this._maybeSendV2Commitment()
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
				// anything for it (S-2.M4).
				const invalid = this._validateNegotiatedInteractiveTx('splice');
				if (invalid) {
					return [{ type: ChannelActionType.ERROR, message: invalid }];
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
		// tx_signatures).
		if (session.getState() === DualFundingState.AWAITING_TX_SIGNATURES) {
			// Audit the negotiated tx before signing anything for it (S-2.M4).
			const invalid = this._validateNegotiatedInteractiveTx('v2');
			if (invalid) {
				return [{ type: ChannelActionType.ERROR, message: invalid }];
			}
			this._state.state = ChannelState.AWAITING_TX_SIGNATURES;
			return this._maybeSendV2Commitment();
		}

		return [];
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
				const { createFundingScript } = require('../script/funding');
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
			weight += isShared ? SHARED_FUNDING_INPUT_WEIGHT : P2WPKH_INPUT_WEIGHT;
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

		if (!valuesKnown) {
			// Cannot audit funds/fees without input values; still enforce weight.
			return weight > 400_000
				? `Transaction weight ${weight} exceeds 400000 WU`
				: null;
		}

		return validateCompletedInteractiveTx({
			remoteInputSats,
			remoteOutputSats,
			remoteContributionSats,
			feeSats: totalInSats - totalOutSats,
			weight,
			feeratePerKw
		});
	}

	private _v2FundingOutpoint(): { txid: Buffer; outputIndex: number } | null {
		const session = this._state.dualFundingSession;
		if (!session || !this._state.remoteBasepoints) return null;
		const built = session.buildTransaction();
		if (!built) return null;
		const {
			buildSpliceTx: buildV2Tx,
			findOutputIndex: findFundingIndex
		} = require('./splice-tx');
		const { createFundingScript } = require('../script/funding');
		let tx;
		try {
			// The interactive-tx final ordering (ascending serial_id) is exactly
			// what buildSpliceTx produces; both sides derive the identical txid.
			tx = buildV2Tx(
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
		const outputIndex = findFundingIndex(tx, funding.p2wshOutput);
		if (outputIndex < 0) return null;
		if (BigInt(tx.outs[outputIndex].value) !== this._state.fundingSatoshis) {
			return null;
		}
		return { txid: Buffer.from(tx.getHash()), outputIndex };
	}

	/**
	 * Send our commitment_signed for the peer's commitment #0 once both sides
	 * have sent tx_complete (BOLT 2 v2 establishment: the commitment_signed
	 * exchange precedes tx_signatures). Idempotent.
	 */
	private _maybeSendV2Commitment(): ChannelAction[] {
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
		const fo = this._v2FundingOutpoint();
		if (!fo) {
			return [
				{
					type: ChannelActionType.ERROR,
					message:
						'v2 funding tx does not pay the negotiated funding output — refusing to sign'
				}
			];
		}
		// signRemoteCommitment reads the funding outpoint from state; set it now,
		// before either side has released any signature. The v2 channel_id is the
		// basepoint-derived id set at accept_channel2 (NOT the funding outpoint) —
		// do not overwrite it here.
		this._state.fundingTxid = fo.txid;
		this._state.fundingOutputIndex = fo.outputIndex;

		const { signature, htlcSignatures } = signRemoteCommitment(
			this._state,
			this._signer,
			this._state.remoteCurrentPerCommitmentPoint,
			0n
		);
		this._v2SentCommitment = true;
		const msg: ICommitmentSignedMessage = {
			channelId: this._state.channelId!,
			signature,
			htlcSignatures
		};
		// Persist BEFORE the message leaves: the peer holds our signature from
		// this point on.
		return [
			{ type: ChannelActionType.PERSIST_STATE },
			sendMsg(MessageType.COMMITMENT_SIGNED, encodeCommitmentSignedMessage(msg))
		];
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
		actions.push(...this._maybeSendV2Commitment());
		if (actions.some((a) => a.type === ChannelActionType.ERROR)) {
			return actions;
		}
		if (this._v2ReceivedCommitment) {
			// Duplicate (retransmit): the first one was verified and adopted.
			return actions;
		}
		if (this._signer && this._state.remoteBasepoints) {
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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'Invalid commitment signature in v2 open'
					}
				];
			}
		}
		this._state.remoteCommitmentSignature = Buffer.from(msg.signature);
		this._state.remoteHtlcSignatures = [];
		this._state.lastSignedCommitFeeratePerKw = getLocalCommitmentFeeRate(
			this._state
		);
		this._v2ReceivedCommitment = true;
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
		if (
			session.getState() !== DualFundingState.AWAITING_TX_SIGNATURES &&
			session.getState() !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return [];
		}
		if (!this._v2SentCommitment || !this._v2ReceivedCommitment) return [];
		const peerSigned = session.getRemoteWitnesses() !== null;
		if (!peerSigned && !this._v2ShouldSignFirst()) return [];

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

		// Funding info was already set when the commitment round started; keep
		// the assignment idempotent for callers that reached here another way.
		// The v2 channel_id is the basepoint-derived id (set at accept_channel2),
		// not the funding outpoint — leave it untouched.
		this._state.fundingTxid = Buffer.from(txid);
		this._state.fundingOutputIndex = outputIndex;

		if (session.getState() === DualFundingState.AWAITING_CHANNEL_READY) {
			this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		}

		const msg: ITxSignaturesMessage = {
			channelId: this._v2ChannelId(),
			txid,
			witnesses
		};

		return [
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

			const actions: ChannelAction[] = [];
			// We must have sent ours first (some peers send tx_signatures before us).
			actions.push(...this._maybeSendSpliceTxSigs());

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
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'splice tx_signatures missing shared-input signature'
					}
				];
			}
			const tx = this.applyPeerSpliceSignature(peerSig, peerWalletWitnesses);
			if (!tx) {
				return [
					{
						type: ChannelActionType.ERROR,
						message: 'invalid peer splice signature'
					}
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
			actions.push({ type: ChannelActionType.BROADCAST_TX, tx: tx.toBuffer() });
			actions.push({
				type: ChannelActionType.WATCH_FUNDING,
				fundingTxid: spliceTxid,
				fundingOutputIndex: this._spliceTx!.newFundingOutputIndex,
				minimumDepth: this._state.minimumDepth
			});

			// If the splice tx confirmed while we were missing the peer's signatures
			// (e.g. the peer completed and broadcast during a disconnect), the
			// confirmation arrived before we could send splice_locked — send it now.
			if (this._state.spliceInFlight?.confirmed) {
				actions.push(...this.sendSpliceLocked());
			}
			return actions;
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
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
			this._state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
			actions.push({ type: ChannelActionType.PERSIST_STATE });
		}

		return actions;
	}

	/**
	 * Initiate RBF on the funding transaction (opener only).
	 */
	initiateTxRbf(
		newFeeratePerkw: number,
		newLocktime?: number
	): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}

		const result = session.initiateRbf(newFeeratePerkw, newLocktime);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to initiate RBF'
				}
			];
		}

		this._state.state = ChannelState.DUAL_FUNDING_V2;

		const msg: ITxInitRbfMessage = {
			channelId: this._v2ChannelId(),
			locktime: result.locktime ?? 0,
			feerate: newFeeratePerkw
		};

		return [sendMsg(MessageType.TX_INIT_RBF, encodeTxInitRbfMessage(msg))];
	}

	/**
	 * Handle tx_init_rbf from peer (acceptor side).
	 */
	handleTxInitRbf(msg: ITxInitRbfMessage): ChannelAction[] {
		const session = this._state.dualFundingSession;
		if (!session) {
			return [
				{ type: ChannelActionType.ERROR, message: 'No dual-funding session' }
			];
		}

		const result = session.handleRbf(msg.feerate, msg.locktime);
		if (!result.ok) {
			return [
				{
					type: ChannelActionType.ERROR,
					message: result.error || 'Failed to handle RBF'
				}
			];
		}

		this._state.state = ChannelState.DUAL_FUNDING_V2;

		// Send tx_ack_rbf
		return [
			sendMsg(
				MessageType.TX_ACK_RBF,
				encodeTxAckRbfMessage({
					channelId: this._v2ChannelId()
				})
			)
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

		session.abort();
		this._state.state = ChannelState.ERRORED;

		const data = reason ? Buffer.from(reason, 'utf8') : Buffer.alloc(0);
		return [
			sendMsg(
				MessageType.TX_ABORT,
				encodeTxAbortMessage({
					channelId: this._v2ChannelId(),
					data
				})
			)
		];
	}

	/**
	 * Handle tx_abort from peer.
	 */
	handleTxAbort(): ChannelAction[] {
		// The echo/ack of a tx_abort we sent (e.g. telling the peer to forget a
		// splice we lost across a restart). Both sides have now forgotten it.
		if (this._spliceAbortPending) {
			this._spliceAbortPending = false;
			return [];
		}

		// A splice tx_abort unwinds the splice and returns the channel to normal
		// operation (the existing channel is unaffected), rather than erroring it.
		if (this._spliceSession && !this._spliceSession.isComplete()) {
			return this.abortSplice('peer sent tx_abort');
		}

		const session = this._state.dualFundingSession;
		if (!session) {
			// Unsolicited tx_abort with nothing in progress (e.g. the peer is
			// discarding a splice we already forgot). BOLT 2: a node that has not
			// itself sent tx_abort MUST echo it back as the ack; it is not a
			// channel failure.
			if (this._state.channelId) {
				return [
					sendMsg(
						MessageType.TX_ABORT,
						encodeTxAbortMessage({
							channelId: this._state.channelId,
							data: Buffer.alloc(0)
						})
					)
				];
			}
			return [];
		}

		session.abort();
		this._state.state = ChannelState.ERRORED;
		return [];
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
	const { DEFAULT_CHANNEL_CONFIG } = require('./types');
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
	const { DEFAULT_CHANNEL_CONFIG } = require('./types');
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
