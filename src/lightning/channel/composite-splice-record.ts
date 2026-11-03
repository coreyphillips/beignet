/**
 * The durable record of a composite splice-out (issue #1922,
 * docs/MULTI-CHANNEL-SPLICE-OUT.md section 5): one transaction that spends
 * the funding outpoints of several channels and pays one destination.
 *
 * Per-channel state stays in each channel's `spliceInFlight`; this record
 * holds the cross-channel facts: which channels take part, what each gives
 * up, the serial ids the composite allocated, the agreed transaction once
 * every session negotiated it, and the stage the operation reached. It is
 * written as a `RecoveryMutation` (`composite_splice`) so a stage change
 * rides the same storage transaction as the channel state and the message it
 * authorizes, and RELEASED is on disk before the first `tx_signatures`
 * leaves. It is operational state with a life of minutes, so it is not a
 * recovery snapshot table: a journal rebuilt from a snapshot drops records
 * older than that snapshot, and restore then applies the missing-record
 * rules of section 5 (a channel whose `spliceInFlight` names the composite's
 * txid is treated as RELEASED).
 *
 * Amounts are decimal strings and ids are hex, as in the FFOR voucher
 * archive, so the record is JSON on every storage backend without a codec.
 */

export type CompositeSpliceStage =
	| 'PLANNED'
	| 'NEGOTIATING'
	| 'COMMITTED'
	| 'PEERS_SIGNED'
	| 'RELEASED'
	| 'BROADCAST'
	| 'LOCKED'
	| 'ABORTED'
	/**
	 * Released, then an input was spent by another transaction (a peer's
	 * force close of its old funding) or a participating channel closed:
	 * the transaction can never confirm. Terminal; the surviving channels'
	 * own splice records follow the single-channel rules from here.
	 */
	| 'CONFLICTED';

/** The stages in the order an operation passes through them. */
export const COMPOSITE_SPLICE_STAGES: readonly CompositeSpliceStage[] = [
	'PLANNED',
	'NEGOTIATING',
	'COMMITTED',
	'PEERS_SIGNED',
	'RELEASED',
	'BROADCAST',
	'LOCKED',
	'ABORTED',
	'CONFLICTED'
];

/** One channel's part in a composite splice. */
export interface ICompositeSpliceChannel {
	/** 32-byte channel id, hex. */
	channelId: string;
	/** The peer across the channel, 33-byte compressed pubkey, hex. */
	peerPubkey: string;
	/** The funding outpoint spent: txid in tx.getHash() internal order, hex. */
	fundingTxid: string;
	fundingOutputIndex: number;
	/** What the channel pays into the destination, sats. */
	debitSats: string;
	/** The channel's share of the fee, sats (ceil(total * debit / amount)). */
	feeSats: string;
	oldCapacitySats: string;
	/** old - debit - fee: the channel's new funding output. */
	newCapacitySats: string;
	/** Serial id of this channel's funding input in every session (even). */
	inputSerialId: string;
	/** Serial id of this channel's new funding output in every session (even). */
	fundingOutputSerialId: string;
}

export interface ICompositeSpliceRecord {
	/** 32 random bytes, hex: the operation id the API returns. */
	id: string;
	stage: CompositeSpliceStage;
	/** In the order the composite's inputs appear (by input serial id). */
	channels: ICompositeSpliceChannel[];
	/** The destination output script, hex. */
	destinationScript: string;
	destinationSerialId: string;
	/** sum(debit), what the destination receives, sats. */
	amountSats: string;
	/** sum(fee_i), what the transaction pays in fees, sats. */
	feeSats: string;
	feeratePerkw: number;
	locktime: number;
	/** The agreed transaction, from COMMITTED on: txid in internal order, hex. */
	txid?: string;
	txHex?: string;
	/** Why the operation ended in ABORTED. */
	reason?: string;
	/** Unix ms. */
	createdAt: number;
	updatedAt: number;
}

/** Whether no further stage change can follow. */
export function compositeSpliceStageIsTerminal(
	stage: CompositeSpliceStage
): boolean {
	return stage === 'LOCKED' || stage === 'ABORTED' || stage === 'CONFLICTED';
}

/**
 * Whether `stage` is at or past `floor` on the forward path. ABORTED and
 * CONFLICTED are outside the path: neither is at or past anything but
 * itself.
 */
export function compositeSpliceStageAtLeast(
	stage: CompositeSpliceStage,
	floor: CompositeSpliceStage
): boolean {
	const outside = (s: CompositeSpliceStage): boolean =>
		s === 'ABORTED' || s === 'CONFLICTED';
	if (outside(stage) || outside(floor)) return stage === floor;
	return (
		COMPOSITE_SPLICE_STAGES.indexOf(stage) >=
		COMPOSITE_SPLICE_STAGES.indexOf(floor)
	);
}

const hex =
	(len: number) =>
	(s: unknown): s is string =>
		typeof s === 'string' && s.length === len && /^[0-9a-f]*$/.test(s);
const hex32 = hex(64);
const hex33 = hex(66);
const anyHex = (s: unknown): s is string =>
	typeof s === 'string' && s.length % 2 === 0 && /^[0-9a-f]*$/.test(s);
const uint = (s: unknown): s is string =>
	typeof s === 'string' &&
	/^(0|[1-9][0-9]*)$/.test(s) &&
	BigInt(s) <= 0xffffffffffffffffn;
const u32 = (n: unknown): n is number =>
	Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 0xffffffff;

/**
 * Validate a record read from storage or a recovery frame, returning a copy
 * with only the known fields. Throws on any field that is not what the type
 * says: a record that fails here is corrupt, and the caller (storage loader,
 * frame decoder) treats it as such rather than acting on it.
 */
export function validateCompositeSpliceRecord(
	value: unknown
): ICompositeSpliceRecord {
	const r = value as ICompositeSpliceRecord;
	if (
		!r ||
		typeof r !== 'object' ||
		!hex32(r.id) ||
		!COMPOSITE_SPLICE_STAGES.includes(r.stage) ||
		!Array.isArray(r.channels) ||
		r.channels.length === 0 ||
		!anyHex(r.destinationScript) ||
		r.destinationScript.length === 0 ||
		!uint(r.destinationSerialId) ||
		!uint(r.amountSats) ||
		!uint(r.feeSats) ||
		!u32(r.feeratePerkw) ||
		!u32(r.locktime) ||
		!Number.isSafeInteger(r.createdAt) ||
		!Number.isSafeInteger(r.updatedAt) ||
		(r.txid !== undefined && !hex32(r.txid)) ||
		(r.txHex !== undefined && (!anyHex(r.txHex) || r.txHex.length === 0)) ||
		(r.reason !== undefined && typeof r.reason !== 'string')
	) {
		throw new Error('Invalid composite splice record');
	}
	const seen = new Set<string>();
	const channels = r.channels.map((c) => {
		if (
			!c ||
			typeof c !== 'object' ||
			!hex32(c.channelId) ||
			!hex33(c.peerPubkey) ||
			!hex32(c.fundingTxid) ||
			!u32(c.fundingOutputIndex) ||
			!uint(c.debitSats) ||
			!uint(c.feeSats) ||
			!uint(c.oldCapacitySats) ||
			!uint(c.newCapacitySats) ||
			!uint(c.inputSerialId) ||
			!uint(c.fundingOutputSerialId) ||
			seen.has(c.channelId)
		) {
			throw new Error('Invalid composite splice record channel');
		}
		seen.add(c.channelId);
		return {
			channelId: c.channelId,
			peerPubkey: c.peerPubkey,
			fundingTxid: c.fundingTxid,
			fundingOutputIndex: c.fundingOutputIndex,
			debitSats: c.debitSats,
			feeSats: c.feeSats,
			oldCapacitySats: c.oldCapacitySats,
			newCapacitySats: c.newCapacitySats,
			inputSerialId: c.inputSerialId,
			fundingOutputSerialId: c.fundingOutputSerialId
		};
	});
	return {
		id: r.id,
		stage: r.stage,
		channels,
		destinationScript: r.destinationScript,
		destinationSerialId: r.destinationSerialId,
		amountSats: r.amountSats,
		feeSats: r.feeSats,
		feeratePerkw: r.feeratePerkw,
		locktime: r.locktime,
		...(r.txid !== undefined ? { txid: r.txid } : {}),
		...(r.txHex !== undefined ? { txHex: r.txHex } : {}),
		...(r.reason !== undefined ? { reason: r.reason } : {}),
		createdAt: r.createdAt,
		updatedAt: r.updatedAt
	};
}
