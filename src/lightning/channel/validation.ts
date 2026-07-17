/**
 * BOLT 2: Channel parameter validation and channel ID derivation.
 */

import crypto from 'crypto';
import {
	IOpenChannelMessage,
	IAcceptChannelMessage
} from '../message/channel-open';
import { isValidPublicKey } from '../crypto/ecdh';
import {
	MAX_ACCEPTED_HTLCS,
	MAX_FUNDING_SATOSHIS,
	MIN_DUST_LIMIT_SATOSHIS,
	MAX_DUST_LIMIT_SATOSHIS,
	isAnchorChannel,
	isTaprootChannel
} from './types';
import { calculateCommitmentFee } from './commitment-builder';
import { ANCHOR_TOTAL_COST } from '../script/anchor';

/**
 * The subset of the open_channel we proposed that accept_channel is validated
 * against. Lets the opener pass its own proposed values (from channel state)
 * without reconstructing a full open_channel message; a full IOpenChannelMessage
 * is structurally assignable here, so existing callers are unaffected.
 */
export type IProposedOpenParams = Pick<
	IOpenChannelMessage,
	| 'temporaryChannelId'
	| 'dustLimitSatoshis'
	| 'channelReserveSatoshis'
	| 'fundingSatoshis'
>;

/**
 * Derive the permanent channel_id from funding txid and output index.
 *
 * Per BOLT 2: channel_id = funding_txid XOR funding_output_index
 * The funding_output_index is encoded as big-endian u16 and XORed
 * into the last 2 bytes of the funding txid.
 */
export function deriveChannelId(
	fundingTxid: Buffer,
	fundingOutputIndex: number
): Buffer {
	if (fundingTxid.length !== 32) {
		throw new Error(`Funding txid must be 32 bytes, got ${fundingTxid.length}`);
	}

	const channelId = Buffer.from(fundingTxid);
	channelId[30] ^= (fundingOutputIndex >> 8) & 0xff;
	channelId[31] ^= fundingOutputIndex & 0xff;

	return channelId;
}

/**
 * Generate a random 32-byte temporary channel ID.
 */
export function generateTemporaryChannelId(): Buffer {
	return crypto.randomBytes(32);
}

/**
 * Derive the v2 (dual-funding) channel_id per BOLT 2:
 *   channel_id = SHA256(lesser-revocation-basepoint || greater-revocation-basepoint)
 * where lesser/greater is the lexicographic order of the two 33-byte revocation
 * basepoints. Both peers compute the same id from the opener's basepoint
 * (open_channel2) and the acceptor's (accept_channel2).
 */
export function deriveV2ChannelId(
	revocationBasepointA: Buffer,
	revocationBasepointB: Buffer
): Buffer {
	const [lesser, greater] =
		Buffer.compare(revocationBasepointA, revocationBasepointB) <= 0
			? [revocationBasepointA, revocationBasepointB]
			: [revocationBasepointB, revocationBasepointA];
	return crypto
		.createHash('sha256')
		.update(Buffer.concat([lesser, greater]))
		.digest();
}

/**
 * Derive the v2 temporary_channel_id sent in open_channel2, before the peer's
 * revocation basepoint is known. Per BOLT 2 it is the v2 channel_id computed
 * with a zeroed-out basepoint for the non-initiator. A zeroed 33-byte basepoint
 * always sorts below a real compressed point (which starts 0x02/0x03), so this
 * is SHA256(0x00*33 || opener_revocation_basepoint).
 */
export function deriveV2TemporaryChannelId(
	openerRevocationBasepoint: Buffer
): Buffer {
	return deriveV2ChannelId(Buffer.alloc(33), openerRevocationBasepoint);
}

/**
 * BOLT 2: every public key and basepoint in open_channel / accept_channel MUST
 * be a valid secp256k1 point. An off-curve basepoint makes every later key
 * derivation (commitment keys, revocation, HTLC keys) fail or, worse, produce
 * unspendable outputs.
 * @returns Error string naming the bad field, or null.
 */
function validateChannelPoints(
	msg: Pick<
		IOpenChannelMessage,
		| 'fundingPubkey'
		| 'revocationBasepoint'
		| 'paymentBasepoint'
		| 'delayedPaymentBasepoint'
		| 'htlcBasepoint'
		| 'firstPerCommitmentPoint'
	>
): string | null {
	const points: Array<[string, Buffer]> = [
		['funding_pubkey', msg.fundingPubkey],
		['revocation_basepoint', msg.revocationBasepoint],
		['payment_basepoint', msg.paymentBasepoint],
		['delayed_payment_basepoint', msg.delayedPaymentBasepoint],
		['htlc_basepoint', msg.htlcBasepoint],
		['first_per_commitment_point', msg.firstPerCommitmentPoint]
	];
	for (const [name, point] of points) {
		if (!isValidPublicKey(point)) {
			return `${name} is not a valid secp256k1 public key`;
		}
	}
	return null;
}

/**
 * Validate open_channel parameters per BOLT 2 requirements.
 * @returns Error string if invalid, null if valid.
 */
export function validateOpenChannelParams(
	msg: IOpenChannelMessage,
	maxFundingSatoshis: bigint = MAX_FUNDING_SATOSHIS
): string | null {
	// funding_satoshis must be > 0
	if (msg.fundingSatoshis === 0n) {
		return 'funding_satoshis must be greater than 0';
	}

	// funding_satoshis must not exceed the cap: 2^24 sat (BOLT 2) unless
	// option_wumbo was negotiated, in which case the caller passes the lifted
	// (but still bounded) per-node maximum.
	if (msg.fundingSatoshis > maxFundingSatoshis) {
		return `funding_satoshis ${msg.fundingSatoshis} exceeds maximum ${maxFundingSatoshis}`;
	}

	// push_msat must not be > 1000 * funding_satoshis
	if (msg.pushMsat > msg.fundingSatoshis * 1000n) {
		return 'push_msat exceeds funding_satoshis * 1000';
	}

	// dust_limit must be >= minimum
	if (msg.dustLimitSatoshis < MIN_DUST_LIMIT_SATOSHIS) {
		return `dust_limit_satoshis ${msg.dustLimitSatoshis} below minimum ${MIN_DUST_LIMIT_SATOSHIS}`;
	}

	// max_accepted_htlcs must be <= 483
	if (msg.maxAcceptedHtlcs > MAX_ACCEPTED_HTLCS) {
		return `max_accepted_htlcs ${msg.maxAcceptedHtlcs} exceeds maximum ${MAX_ACCEPTED_HTLCS}`;
	}

	// channel_reserve must be >= dust_limit
	if (msg.channelReserveSatoshis < msg.dustLimitSatoshis) {
		return 'channel_reserve_satoshis must be >= dust_limit_satoshis';
	}

	// feerate_per_kw must be > 0
	if (msg.feeratePerKw === 0) {
		return 'feerate_per_kw must be greater than 0';
	}

	// to_self_delay must be > 0
	if (msg.toSelfDelay === 0) {
		return 'to_self_delay must be greater than 0';
	}

	// to_self_delay must be <= 2016
	if (msg.toSelfDelay > 2016) {
		return `to_self_delay ${msg.toSelfDelay} exceeds maximum 2016`;
	}

	// feerate_per_kw must be <= 100,000
	if (msg.feeratePerKw > 100_000) {
		return `feerate_per_kw ${msg.feeratePerKw} exceeds maximum 100000`;
	}

	// funding_pubkey must be 33 bytes
	if (msg.fundingPubkey.length !== 33) {
		return 'funding_pubkey must be 33 bytes';
	}

	// All keys/basepoints must be valid curve points
	const pointError = validateChannelPoints(msg);
	if (pointError) {
		return pointError;
	}

	// BOLT 2 acceptor MUSTs on the initial commitment. The opener pays the
	// commitment fee (plus both 330-sat anchors on anchor channels), so its
	// balance after push_msat must cover that in full, and at least one side
	// must start above channel_reserve or neither commitment output exists.
	const anchor = isAnchorChannel(msg.channelType ?? null);
	const commitCostMsat =
		(calculateCommitmentFee(
			msg.feeratePerKw,
			0,
			anchor,
			isTaprootChannel(msg.channelType ?? null)
		) +
			(anchor ? ANCHOR_TOTAL_COST : 0n)) *
		1000n;
	const funderMsat = msg.fundingSatoshis * 1000n - msg.pushMsat;
	if (funderMsat < commitCostMsat) {
		return 'funder cannot afford the initial commitment fee';
	}
	const reserveMsat = msg.channelReserveSatoshis * 1000n;
	if (
		funderMsat - commitCostMsat <= reserveMsat &&
		msg.pushMsat <= reserveMsat
	) {
		return 'both initial commitment outputs are below channel_reserve';
	}

	return null;
}

/**
 * Validate accept_channel parameters against the corresponding open_channel.
 * @returns Error string if invalid, null if valid.
 */
export function validateAcceptChannelParams(
	open: IProposedOpenParams,
	accept: IAcceptChannelMessage
): string | null {
	// temporary_channel_id must match
	if (!open.temporaryChannelId.equals(accept.temporaryChannelId)) {
		return 'temporary_channel_id does not match';
	}

	// dust_limit must be >= minimum
	if (accept.dustLimitSatoshis < MIN_DUST_LIMIT_SATOSHIS) {
		return `dust_limit_satoshis ${accept.dustLimitSatoshis} below minimum ${MIN_DUST_LIMIT_SATOSHIS}`;
	}

	// dust_limit must be <= a sane maximum. An unbounded dust_limit is the FS-1
	// fund-loss: the acceptor sets it near our whole balance, so every remote
	// commitment we build trims our to_remote output as "dust" and we sign it.
	if (accept.dustLimitSatoshis > MAX_DUST_LIMIT_SATOSHIS) {
		return `dust_limit_satoshis ${accept.dustLimitSatoshis} exceeds maximum ${MAX_DUST_LIMIT_SATOSHIS}`;
	}

	// max_accepted_htlcs must be <= 483
	if (accept.maxAcceptedHtlcs > MAX_ACCEPTED_HTLCS) {
		return `max_accepted_htlcs ${accept.maxAcceptedHtlcs} exceeds maximum ${MAX_ACCEPTED_HTLCS}`;
	}

	// channel_reserve must be >= dust_limit of the opener
	if (accept.channelReserveSatoshis < open.dustLimitSatoshis) {
		return 'acceptor channel_reserve must be >= opener dust_limit';
	}

	// opener channel_reserve must be >= acceptor dust_limit
	if (open.channelReserveSatoshis < accept.dustLimitSatoshis) {
		return 'opener channel_reserve must be >= acceptor dust_limit';
	}

	// channel_reserve from both sides must not exceed funding
	if (
		accept.channelReserveSatoshis + open.channelReserveSatoshis >
		open.fundingSatoshis
	) {
		return 'combined channel reserves exceed funding_satoshis';
	}

	// to_self_delay must be > 0
	if (accept.toSelfDelay === 0) {
		return 'to_self_delay must be greater than 0';
	}

	// to_self_delay must be <= 2016
	if (accept.toSelfDelay > 2016) {
		return `to_self_delay ${accept.toSelfDelay} exceeds maximum 2016`;
	}

	// funding_pubkey must be 33 bytes
	if (accept.fundingPubkey.length !== 33) {
		return 'funding_pubkey must be 33 bytes';
	}

	// All keys/basepoints must be valid curve points
	const pointError = validateChannelPoints(accept);
	if (pointError) {
		return pointError;
	}

	return null;
}

// Bitcoin script opcodes used by the standard shutdown script forms.
const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;
const OP_EQUAL = 0x87;
const OP_0 = 0x00;
const OP_1 = 0x51;
const OP_16 = 0x60;
const OP_RETURN = 0x6a;
const OP_PUSHDATA1 = 0x4c;

/**
 * Validate a peer-supplied shutdown scriptPubkey per BOLT 2.
 *
 * A receiving node MUST fail the channel (and never pay a cooperative-close
 * output to it) unless the script is one of the allowed forms:
 *   - P2PKH:  OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
 *   - P2SH:   OP_HASH160 <20-byte hash> OP_EQUAL
 *   - P2WPKH: OP_0 <20-byte hash>
 *   - P2WSH:  OP_0 <32-byte hash>
 *   - Any other valid witness program (version 1..16, 2..40 byte program)
 *     ONLY if option_shutdown_anysegwit was negotiated.
 *   - OP_RETURN with a 6..75-byte push (or PUSHDATA1 76..80) ONLY if
 *     option_simple_close was negotiated (a dust-balance closer burns its
 *     output; the output amount MUST be 0).
 *
 * @param script The remote scriptPubkey.
 * @param allowAnySegwit Whether option_shutdown_anysegwit was negotiated.
 * @param allowOpReturn Whether option_simple_close was negotiated.
 * @returns true if the script is an acceptable shutdown destination.
 */
export function isValidShutdownScript(
	script: Buffer,
	allowAnySegwit = false,
	allowOpReturn = false
): boolean {
	if (!script || script.length === 0) return false;

	// OP_RETURN forms (option_simple_close only):
	//   6a <push 6..75> <data>            — length = data + 2
	//   6a 4c <len 76..80> <data>         — length = data + 3
	if (allowOpReturn && script[0] === OP_RETURN) {
		if (
			script.length >= 8 &&
			script[1] >= 0x06 &&
			script[1] <= 0x4b &&
			script.length === script[1] + 2
		) {
			return true;
		}
		if (
			script.length >= 79 &&
			script[1] === OP_PUSHDATA1 &&
			script[2] >= 0x4c &&
			script[2] <= 0x50 &&
			script.length === script[2] + 3
		) {
			return true;
		}
		return false;
	}

	// P2PKH: 25 bytes — 76 a9 14 <20> 88 ac
	if (
		script.length === 25 &&
		script[0] === OP_DUP &&
		script[1] === OP_HASH160 &&
		script[2] === 0x14 &&
		script[23] === OP_EQUALVERIFY &&
		script[24] === OP_CHECKSIG
	) {
		return true;
	}

	// P2SH: 23 bytes — a9 14 <20> 87
	if (
		script.length === 23 &&
		script[0] === OP_HASH160 &&
		script[1] === 0x14 &&
		script[22] === OP_EQUAL
	) {
		return true;
	}

	// P2WPKH: 22 bytes — 00 14 <20>
	if (script.length === 22 && script[0] === OP_0 && script[1] === 0x14) {
		return true;
	}

	// P2WSH: 34 bytes — 00 20 <32>
	if (script.length === 34 && script[0] === OP_0 && script[1] === 0x20) {
		return true;
	}

	// Any other witness program (e.g. P2TR) — only with option_shutdown_anysegwit.
	if (allowAnySegwit) {
		const version = script[0];
		const pushLen = script[1];
		const isWitnessVersion =
			version === OP_0 || (version >= OP_1 && version <= OP_16);
		// program length is 2..40 bytes and must match the push opcode + total length
		if (
			isWitnessVersion &&
			pushLen >= 0x02 &&
			pushLen <= 0x28 &&
			script.length === pushLen + 2
		) {
			return true;
		}
	}

	return false;
}
