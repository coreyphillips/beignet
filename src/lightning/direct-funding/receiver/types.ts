/**
 * The receiver engine's injected surface: what it needs from the node, and
 * what the operator may tune (issue #612, LFBW port #532 workstream 4C).
 *
 * Declared here rather than importing LightningNode, the shape 3A established
 * with IJitManagerDeps: the engine is a library module driven by a stub in
 * tests, and 4D is what binds these to a real node.
 */

import type { Transaction } from 'bitcoinjs-lib';
import type { ISpliceWalletInput } from '../../channel/channel';
import type { DirectFundingRequestStore } from '../requests';
import type { DfTransportLog } from '../transport/types';

// ─────────────── Limits ───────────────

/**
 * Sessions that may be driving a channel or splice at once. Each one holds a
 * peer negotiation open, so this is the real exposure a stranger can create.
 *
 * The fork read its cap AFTER inserting the current session and compared with
 * `>`, so its stated 4 was really 6 (defect D16). Here the count is taken
 * before insertion and compared with `>=`, and a test pins the number.
 */
export const DF_MAX_INFLIGHT_OFFER_SESSIONS = 4;

/**
 * Offer records held at once, live and tombstoned together. A tombstone is
 * small but it is not free, and rev 2 wants it to outlive the exchange, so the
 * map needs a ceiling of its own: the fork capped only the in-flight count and
 * kept every session forever, in a MODULE-level map shared by every node in the
 * process, each one retaining its full outbound frame log (defect D15).
 */
export const DF_MAX_OFFER_SESSIONS = 512;

/** Offers one request may spend a session on over its whole life (rev 2: 3). */
export const DF_MAX_REQUEST_ATTEMPTS = 3;

/**
 * Protocol floor under any configured minimum. Below this the payer's own fee
 * share dominates the payment and a channel is the wrong instrument for it.
 */
export const DF_HARD_MIN_OFFER_AMOUNT_SAT = 5_000n;

/** How long an in-flight session may hold its slot before it is swept. */
export const DF_OFFER_SESSION_TTL_MS = 15 * 60 * 1000;

/**
 * How long a FAILED offer's outpoint stays reserved. Rev 2 asks for a cooldown
 * after failure specifically: releasing instantly lets the same coin be
 * re-offered under a fresh offer id straight away and burn session after
 * session. A success releases immediately, since the coin is spent.
 */
export const DF_OUTPOINT_COOLDOWN_MS = 60_000;

/** Time from the ack to a final interactive transaction. */
export const DF_NEGOTIATION_TIMEOUT_MS = 120_000;

/** Time from the sign request to the payer's witness. */
export const DF_WITNESS_TIMEOUT_MS = 120_000;

/** How often expired sessions, reservations and attempt records are swept. */
export const DF_RECEIVER_SWEEP_INTERVAL_MS = 30_000;

/** Feerate a direct-funded splice negotiates at, when none is configured. */
export const DF_DEFAULT_SPLICE_FEERATE_PERKW = 500;

// ─────────────── Config ───────────────

export interface IDfReceiverConfig {
	/** Receiver's own minimum; the 5000 sat protocol floor applies under it. */
	minAmountSat?: bigint;
	/** Largest single offer this receiver will serve. Unset means no ceiling. */
	maxAmountSat?: bigint;
	/**
	 * The exact nSequence a payer must commit to. The payer signs it, so a
	 * value we did not put in the transaction is a session spent on a witness
	 * that can never validate (defect D9).
	 */
	requiredSequence?: number;
	maxInflightSessions?: number;
	maxSessions?: number;
	maxRequestAttempts?: number;
	sessionTtlMs?: number;
	outpointCooldownMs?: number;
	negotiationTimeoutMs?: number;
	witnessTimeoutMs?: number;
	sweepIntervalMs?: number;
	spliceFeeratePerKw?: number;
	/**
	 * Serve offers by splicing an existing channel with the liquidity peer
	 * rather than opening a new one. Rev 2 classes splice-in as an extension;
	 * off leaves every offer on the simpler new-channel path.
	 */
	allowSplice?: boolean;
}

// ─────────────── Node surface ───────────────

/**
 * The chain queries the engine makes. Structurally a subset of IChainBackend,
 * so 4D passes the node's backend straight through. Note that ElectrumBackend
 * caches nothing, so every call is a round trip: the engine resolves each
 * offered transaction exactly once and holds it for the session.
 */
export interface IDfChainSource {
	/** Raw transaction by DISPLAY txid. */
	getTransaction(txid: string): Promise<Buffer>;
	/** Electrum-style script hash (see chain/chain-watcher computeScriptHash). */
	listUnspent?(scriptHash: string): Promise<
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	>;
	getScriptHashHistory?(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>>;
}

/** What Channel.getPendingV2FundingTx hands back, verbatim. */
export interface IDfPendingV2FundingTx {
	tx: Transaction;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	prevouts: { scripts: Buffer[]; values: bigint[] } | null;
	owedExternalInputs: Array<{
		inputIndex: number;
		prevTxid: Buffer;
		prevOutputIndex: number;
	}>;
}

/** What Channel.getPendingSpliceTx hands back, verbatim. */
export interface IDfPendingSpliceTx {
	tx: Transaction;
	spliceTxid: Buffer;
	sharedInputIndex: number;
	newFundingOutputIndex: number;
	prevouts: { scripts: Buffer[]; values: bigint[] } | null;
	owedExternalInputs: Array<{
		inputIndex: number;
		prevTxid: Buffer;
		prevOutputIndex: number;
	}>;
}

/**
 * A started v2 open. The id is read through a function rather than captured
 * because a v2 open answers to its temporary id until accept_channel2 and to
 * its permanent id afterwards, and the unwind has to name whichever is current.
 */
export interface IDfChannelHandle {
	channelId(): Buffer;
}

export interface IDfOpenParams {
	fundingSatoshis: bigint;
	contribution: { inputs: ISpliceWalletInput[]; changeScript: Buffer };
	/** Zero-conf: only ever true for an authenticated payer in the trusted set. */
	trusted?: boolean;
}

/** The `channel:txsigs-needed` payload, narrowed to what the engine reads. */
export interface IDfTxSigsNeeded {
	channelId: Buffer;
	externalInputIndices?: number[];
}

/** The `channel:splice-txsigs-needed` payload. */
export interface IDfSpliceTxSigsNeeded {
	channelId: Buffer;
	externalInputIndices: number[];
}

export interface IDfReceiverDeps {
	/** Sign with the node identity key; zbase32, i.e. LightningNode.signMessage. */
	signMessage(message: string): string;
	/** Requests this node minted (4A). A session exists only for one of these. */
	requests: DirectFundingRequestStore;
	chain: IDfChainSource;
	/** The liquidity peer every direct-funded channel is negotiated with. */
	liquidityPeer(): string | null;
	/** A channel with this peer a splice could ride, or null. */
	usableChannelWith(peerHex: string): Buffer | null;
	/** Funding pubkeys of a channel, for the attestation. */
	fundingPubkeys(channelId: Buffer): { local: Buffer; remote: Buffer } | null;
	/** Upstream's own zero-conf gate (zero-conf.ts canOpenZeroConfTo). */
	canOpenZeroConfTo(peerHex: string): boolean;
	/**
	 * Is this AUTHENTICATED payer one the operator paired with? Reads the
	 * zero-conf trusted set in production and never writes it: membership there
	 * is symmetric, and this decision only takes a risk rather than granting
	 * one, so it needs no set of its own (3A needed one because it was
	 * granting).
	 */
	isTrustedPayer(peerHex: string): boolean;
	openChannelV2(peerHex: string, params: IDfOpenParams): IDfChannelHandle;
	abortDualFundedOpen(
		channelId: Buffer,
		reason: string
	): { ok: boolean; error?: string };
	spliceInWithInputs(
		channelId: Buffer,
		amountSats: bigint,
		inputs: ISpliceWalletInput[],
		changeScript: Buffer,
		feeratePerKw: number
	): { ok: boolean; error?: string };
	abortSplice(
		channelId: Buffer,
		reason: string
	): { ok: boolean; error?: string };
	getPendingV2FundingTx(channelId: Buffer): IDfPendingV2FundingTx | null;
	getPendingSpliceTx(channelId: Buffer): IDfPendingSpliceTx | null;
	provideV2ExternalWitness(
		channelId: Buffer,
		prevTxid: Buffer,
		prevOutputIndex: number,
		witness: Buffer[]
	): { ok: boolean; error?: string };
	provideSpliceExternalWitness(
		channelId: Buffer,
		prevTxid: Buffer,
		prevOutputIndex: number,
		witness: Buffer[]
	): { ok: boolean; error?: string };
	/** Subscribe to `channel:txsigs-needed`; the return value unsubscribes. */
	onTxSigsNeeded(cb: (e: IDfTxSigsNeeded) => void): () => void;
	/** Subscribe to `channel:splice-txsigs-needed`. */
	onSpliceTxSigsNeeded(cb: (e: IDfSpliceTxSigsNeeded) => void): () => void;
	now?(): number;
	/** Structured-log sink, the same one 4B's lanes take. */
	log?: DfTransportLog;
}

export const DF_LOG_OFFER_DROPPED = 'df_offer_dropped';
export const DF_LOG_OFFER_DECLINED = 'df_offer_declined';
export const DF_LOG_OFFER_ACCEPTED = 'df_offer_accepted';
export const DF_LOG_OFFER_FAILED = 'df_offer_failed';
export const DF_LOG_OFFER_COMPLETED = 'df_offer_completed';

/** Why an offer frame went nowhere. Silence stays on the wire (4B's rule). */
export enum DfOfferDropReason {
	/** The payload is not a sealed frame, or not an OPENING one. */
	NOT_AN_OPENING_FRAME = 'not_an_opening_frame',
	/** Sealed to a request this node did not mint, or already forgotten. */
	UNKNOWN_REQUEST = 'unknown_request',
	/** The lane bound the frame to one request and the seal names another. */
	REQUEST_ID_MISMATCH = 'request_id_mismatch',
	/** The seal did not authenticate. */
	NOT_AUTHENTICATED = 'not_authenticated',
	/** It opened, and the plaintext is not a message of this subtype. */
	MALFORMED_MESSAGE = 'malformed_message',
	/** A witness frame no live session could open or claim. */
	NO_SESSION = 'no_session',
	/** An offer id already being admitted on another frame. */
	ADMISSION_IN_PROGRESS = 'admission_in_progress'
}
