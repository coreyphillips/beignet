/**
 * Third-party direct funding: shared types, limits and refusals (issue #610,
 * LFBW port #532 workstream 4A).
 *
 * The protocol authority for every byte in this directory is
 * "Third-Party Direct Funding of Lightning Channels" revision 2 (the bLIP
 * draft circulated with the LFBW app). An unrelated payer's on-chain payment
 * becomes the receiver's channel funding transaction directly: the receiver
 * mints a signed request envelope, hands it out inside a BIP 21 URI, and the
 * payer contributes its input to a dual-funded open after verifying, in the
 * exact bytes it signs, that its coin funds a channel output the receiver's
 * node key attested.
 *
 * This module is the substrate: the envelope codec (rev 2 "The payment
 * request envelope"), the sealed frame layer (rev 2 "Frame encryption"), the
 * six message codecs (rev 2 "The funding protocol") and the durable request
 * record (rev 2 "Request lifecycle requirements"). It reads and writes no
 * transport and touches no channel.
 */

import { Network } from '../invoice/types';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH,
	SIGNET_CHAIN_HASH,
	TESTNET_CHAIN_HASH
} from '../channel/types';

// ─────────────── Sizes ───────────────

export const DF_ENVELOPE_VERSION = 3;
export const DF_REQUEST_ID_BYTES = 16;
export const DF_CHAIN_HASH_BYTES = 32;
export const DF_NODE_ID_BYTES = 33;
export const DF_RECEIPT_HASH_BYTES = 32;
export const DF_PREIMAGE_BYTES = 32;
export const DF_SIGNATURE_BYTES = 65;
export const DF_PATH_SECRET_BYTES = 32;
export const DF_OFFER_ID_BYTES = 16;

/** Smallest possible envelope: no amount, no transports. */
export const DF_ENVELOPE_MIN_BYTES = 220;

/**
 * Decode ceiling for a whole envelope. A request has to survive a scannable
 * QR, so a real one is a few hundred bytes; this only stops a hostile string
 * from making a payer walk megabytes before the first refusal.
 */
export const DF_MAX_ENVELOPE_BYTES = 8192;

/**
 * The BIP 21 query parameter carrying the envelope. Named here rather than in
 * a consumer: the LFBW dashboard decoder re-derives the field offsets by hand
 * because the fork never named the parameter in beignet at all.
 */
export const DF_BIP21_PARAM = 'bgnq';

/**
 * Longest life a request may be minted or accepted with. Rev 2 leaves the u48
 * expiry unbounded, which lets one envelope hold a store slot and a path
 * secret effectively forever; a payment request is a short-lived artifact (the
 * reference TTL is an hour) and a week is already far beyond any legitimate
 * use.
 */
export const DF_MAX_REQUEST_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Default life of a minted request, the rev 2 reference implementation's. */
export const DF_DEFAULT_REQUEST_TTL_MS = 60 * 60 * 1000;

/** u48 milliseconds, the widest value the expiry field can carry. */
export const DF_MAX_EXPIRES_AT = 0xffffffffffff;

/** No request can ask for more than the money supply. */
export const DF_MAX_AMOUNT_SAT = 21_000_000n * 100_000_000n;

/**
 * Decode ceiling for one protocol message. The BOLT 4 large onion form
 * (32768 bytes of routing info) is the tightest lane the protocol runs over,
 * so nothing above it can be delivered anyway; 4B enforces the exact per-lane
 * budget, this only bounds what a peer can make a decoder walk.
 */
export const DF_MAX_MESSAGE_BYTES = 32_768;

/** Rev 2 caps a direct-funded transaction at 16 inputs and 8 outputs. */
export const DF_MAX_PREVOUTS = 16;
export const DF_MAX_TX_OUTPUTS = 8;
export const DF_MAX_RAW_TX_BYTES = 20_000;
export const DF_MAX_SCRIPT_BYTES = 520;
/** The ownership proof admits P2WPKH and P2TR key path, so one or two items. */
export const DF_MAX_WITNESS_ITEMS = 8;
export const DF_MAX_WITNESS_ITEM_BYTES = 1024;
/** Refusal reasons are ours; a long one is truncated rather than refused. */
export const DF_MAX_REASON_BYTES = 200;
/** Descriptors a receiver may sign into one envelope. */
export const DF_MAX_TRANSPORTS = 8;
/** Hops in an onion transport's blinded path (rev 2 mints [intro, receiver]). */
export const DF_MAX_BLINDED_HOPS = 8;

// ─────────────── Refusals ───────────────

export enum DirectFundingErrorCode {
	/** Structurally undecodable: truncated, trailing bytes, bad field width. */
	MALFORMED = 'MALFORMED',
	UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
	EXPIRED = 'EXPIRED',
	/** An expiry so far out the request would hold its slot indefinitely. */
	EXPIRY_TOO_DISTANT = 'EXPIRY_TOO_DISTANT',
	/** The signature does not recover a public key at all. */
	INVALID_SIGNATURE = 'INVALID_SIGNATURE',
	/** It recovers one, and it is not the node the envelope names. */
	WRONG_SIGNER = 'WRONG_SIGNER',
	WRONG_CHAIN = 'WRONG_CHAIN',
	/** The outstanding-request cap is full; a later mint succeeds. */
	TOO_MANY_REQUESTS = 'TOO_MANY_REQUESTS',
	/** The request's secrets did not reach durable storage. */
	NOT_PERSISTED = 'NOT_PERSISTED',
	/** No transport in the envelope could carry a frame to the receiver. */
	UNREACHABLE = 'UNREACHABLE',
	/** The request fixes no amount and the caller named none. */
	AMOUNT_REQUIRED = 'AMOUNT_REQUIRED',
	/** The caller's amount contradicts the one the request fixed. */
	AMOUNT_MISMATCH = 'AMOUNT_MISMATCH',
	/**
	 * No single coin covers the payment and its fee ceiling. Its own code
	 * because a payer that cannot fund is not a payer that could not connect,
	 * and only one of those is worth falling back to a plain address payment on.
	 */
	NO_SUITABLE_UTXO = 'NO_SUITABLE_UTXO',
	/** The receiver refused the offer, with its reason. */
	OFFER_DECLINED = 'OFFER_DECLINED',
	/** The transaction we were asked to sign failed one of rev 2's checks. */
	SIGN_REQUEST_REFUSED = 'SIGN_REQUEST_REFUSED',
	/** The exchange ran out of time before the witness left the device. */
	EXCHANGE_TIMEOUT = 'EXCHANGE_TIMEOUT'
}

/**
 * A direct-funding refusal carrying WHY. Rev 2 requires malformed, expired,
 * wrong-chain, invalid-signature and wrong-signer envelopes to die on the
 * payer's device with the reason; a code rather than a message means 4D can
 * answer each with its own status without matching substrings (issue #464).
 */
export class DirectFundingError extends Error {
	code: DirectFundingErrorCode;

	constructor(code: DirectFundingErrorCode, message: string) {
		super(message);
		this.name = 'DirectFundingError';
		this.code = code;
	}
}

/** Shorthand for the commonest refusal. */
export function malformed(what: string): DirectFundingError {
	return new DirectFundingError(DirectFundingErrorCode.MALFORMED, what);
}

// ─────────────── Transport descriptors ───────────────

/**
 * `transport_descriptor = u8 type || u16 value_length || value`. The length
 * prefix is the whole forward-compatibility story: a decoder skips a type it
 * does not know without losing the rest of the envelope.
 */
export enum DfTransportType {
	/** `u8 host_len || host || u16 port` */
	DIRECT_PEER = 1,
	/** Blinded path to the receiver; the preferred transport. */
	ONION_MESSAGE = 2,
	/** `33 relay_node_id || u8 host_len || host || u16 port` */
	LSP_RELAY = 3,
	/**
	 * Non-Lightning rendezvous (the deferred hyperswarm transport, #533).
	 * Decoded and skipped, never emitted by anything in this campaign.
	 */
	RENDEZVOUS = 4
}

export interface IDfDirectPeerTransport {
	type: DfTransportType.DIRECT_PEER;
	host: string;
	port: number;
}

export interface IDfBlindedHop {
	blindedNodeId: Buffer;
	encryptedData: Buffer;
}

export interface IDfOnionTransport {
	type: DfTransportType.ONION_MESSAGE;
	/** Where the introduction node is reachable. */
	host: string;
	port: number;
	introNodeId: Buffer;
	pathKey: Buffer;
	hops: IDfBlindedHop[];
}

export interface IDfRelayTransport {
	type: DfTransportType.LSP_RELAY;
	relayNodeId: Buffer;
	host: string;
	port: number;
}

/**
 * A descriptor whose type this decoder does not implement, kept verbatim so
 * the envelope still re-encodes byte for byte (the receiver signed these
 * bytes) and so a later registry can claim the type without a new version.
 */
export interface IDfUnknownTransport {
	type: number;
	value: Buffer;
}

export type DfTransportDescriptor =
	| IDfDirectPeerTransport
	| IDfOnionTransport
	| IDfRelayTransport
	| IDfUnknownTransport;

export function isUnknownTransport(
	t: DfTransportDescriptor
): t is IDfUnknownTransport {
	return (t as IDfUnknownTransport).value !== undefined;
}

// ─────────────── The request envelope ───────────────

export interface IDfRequestEnvelope {
	version: number;
	requestId: Buffer;
	/** BOLT chain_hash of the chain this request may be paid on. */
	chainHash: Buffer;
	receiverNodeId: Buffer;
	/** Milliseconds since epoch (u48 on the wire). */
	expiresAt: number;
	/** Present only when the receiver fixed an amount. */
	amountSat?: bigint;
	receiptHash: Buffer;
	/** Per-request secp256k1 public key; the node identity key never seals. */
	encryptionKey: Buffer;
	transports: DfTransportDescriptor[];
	/** Raw 65-byte compact recoverable signature. */
	signature: Buffer;
	/**
	 * The exact unsigned bytes this signature covers. Carried rather than
	 * re-derived so verification never depends on encode being a byte-perfect
	 * inverse of decode: an envelope with an unknown transport type or an
	 * unknown flags bit still verifies, where a re-encoding verifier would
	 * quietly reject the forward compatibility the format was designed for.
	 */
	signedBytes: Buffer;
}

// ─────────────── Persisted request record ───────────────

/**
 * The funding an attempt left in flight, as a restarted receiver reads it.
 *
 * The outpoint is the payer's coin and the key the channel's owed-witness
 * event resolves on; the channel id is what the negotiated transaction and the
 * witness delivery are addressed to. Both are recorded once the interactive
 * transaction is final, which for either kind is the point where the channel's
 * own record became durable and the id stopped changing.
 */
export interface IDfAttemptFunding {
	/** `txid:vout`, display byte order. */
	outpoint: string;
	channelId: string;
	/** A splice into an existing channel rather than a new v2 open. */
	splice: boolean;
	/**
	 * SHA256 of the offer bytes the funding was negotiated for. A re-sent offer
	 * is served from the funding only if it is that offer to the byte, which is
	 * the refusal a live duplicate already gets from its session record.
	 */
	contentHash: string;
	/**
	 * The payer's ephemeral public key for the lane this funding was negotiated
	 * on, 33-byte hex. It travels on the OPENING frame only, so without it a
	 * restarted receiver cannot open the witness frame the payer sends next: the
	 * lane keys are an ECDH over this key, and the payer sends its witness once.
	 */
	payerEphemeralKey: string;
}

/**
 * One outstanding request. Every field is a secret the receiver needs to
 * answer an envelope it already handed out, which is why this lives in the
 * encrypted wallet-data store rather than a JSON file next to it.
 */
export interface IDfRequestRecord {
	/** 16-byte hex: the frame AAD and the primary store index. */
	requestId: string;
	/** 32-byte hex: the envelope field and the receipt index. */
	receiptHash: string;
	/** Revealed only after broadcast, as the delivery receipt. */
	preimageHex: string;
	/** Per-request secp256k1 private key, never the node key. */
	encryptionPrivateKeyHex: string;
	/**
	 * The blinded path's private path_id. It appears nowhere in the envelope:
	 * a payer-visible value would let any request holder mint a route that
	 * passes the issued-path check (rev 2 "PATH_ID PRIVACY").
	 */
	onionPathSecretHex: string;
	/** Milliseconds since epoch, matching the envelope's u48. */
	expiresAt: number;
	/**
	 * The amount the envelope fixed, as decimal satoshis, when it fixed one.
	 * Persisted rather than derived from the envelope the payer holds: the
	 * envelope is signed but it is the PAYER's copy, and the offer that arrives
	 * carries only an amount of the payer's choosing. Without the receiver's own
	 * record of it a fixed-amount request can be settled for any amount inside
	 * the global bounds.
	 */
	amountSat?: string;
	/**
	 * Set when the receipt preimage was revealed. The record is TOMBSTONED,
	 * not deleted: the encryption key has to survive so a payer whose receipt
	 * frame was lost can re-send its offer and be replayed the recorded
	 * responses verbatim (rev 2 "at-least-once delivery, exactly-once
	 * effects"). 4C owns the session half; this is the persistence half.
	 */
	revealedAt?: number;
	/**
	 * The offer this request was paid by, and the funding it was paid into.
	 * Written in the same store write as the tombstone, so a receiver restarted
	 * after a successful exchange can still replay the receipt: the session
	 * that recorded it lives in memory only, and without this the payer whose
	 * receipt frame was lost gets a bare "already paid" and no proof of it.
	 */
	paidBy?: { offerIdHex: string; fundingTxidHex: string };
	/** Offers this request has spent a funding session on, over its whole life. */
	attempts?: number;
	/**
	 * The offer holding this request's one funding session, and when that slot
	 * lapses. Durable for the same reason the count is: a restart mid-session
	 * would otherwise let the duplicate offer that follows it begin a SECOND
	 * channel session for one payment.
	 */
	activeAttempt?: {
		offerIdHex: string;
		expiresAt: number;
		/**
		 * The funding this attempt negotiated, once there is one. Written before
		 * the payer is asked to sign, and what a restarted receiver rebinds the
		 * re-sent offer to: the session that drove it was memory only, so without
		 * this the channel is stranded with the payer's input unwitnessed and the
		 * request goes free at the session TTL (issue #635).
		 */
		funding?: IDfAttemptFunding;
	};
	/** Reserved for the deferred rendezvous transport (#533), never minted. */
	swarmSeedHex?: string;
}

// ─────────────── Chain binding ───────────────

/** The BOLT chain_hash a request minted on this network must carry. */
export function chainHashForNetwork(network: Network): Buffer {
	switch (network) {
		case Network.MAINNET:
			return BITCOIN_CHAIN_HASH;
		case Network.TESTNET:
			return TESTNET_CHAIN_HASH;
		case Network.SIGNET:
			return SIGNET_CHAIN_HASH;
		default:
			return REGTEST_CHAIN_HASH;
	}
}

// ─────────────── Reader ───────────────

/**
 * Bounds-checked cursor. Shared by the envelope and message codecs so every
 * variable-width read in this module refuses a truncated field by name rather
 * than returning a short buffer that reads as a legitimate (and wrong) value.
 */
export class ByteReader {
	private off = 0;

	constructor(private readonly buf: Buffer) {}

	take(n: number, what: string): Buffer {
		if (n < 0 || this.off + n > this.buf.length) {
			throw malformed(`${what} runs past the end of the payload`);
		}
		const out = this.buf.subarray(this.off, this.off + n);
		this.off += n;
		return out;
	}

	u8(what: string): number {
		return this.take(1, what)[0];
	}

	u16(what: string): number {
		return this.take(2, what).readUInt16BE(0);
	}

	u32(what: string): number {
		return this.take(4, what).readUInt32BE(0);
	}

	u64(what: string): bigint {
		return this.take(8, what).readBigUInt64BE(0);
	}

	remaining(): number {
		return this.buf.length - this.off;
	}
}
