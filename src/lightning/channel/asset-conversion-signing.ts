/**
 * The exchange objects of an asset conversion's signing (#2151 Step 4b):
 * each side's consent, asset authorization, `final_ack`, construction
 * checkpoint and exit share, in memory only. Nothing here is written; an
 * attempt that ends drops them, and nothing resumes. Internal: not in the
 * barrel.
 */
import { sha256 } from '../crypto/provider';
import {
	ASSET_OPEN_CHUNK_SIZE,
	ASSET_OPEN_OBJECT_LIMIT,
	AssetOpenObjectReceiver,
	decodeAssetOpenConsent,
	decodeAssetOpenFrame,
	encodeAssetOpenConsent,
	encodeAssetOpenFrame
} from '../message/asset-open';
import { BeignetCustomSubtype as Sub } from '../message/custom';
import type { AssetOpenPair } from './asset-opening-provider';

export const CONVERSION_SIGNING_TEXTS = {
	premature: 'Premature asset conversion signing object',
	conflicting: 'Conflicting asset conversion signing object',
	consent: 'Invalid asset conversion consent',
	frame: 'Invalid asset conversion layout frame',
	unexpected: 'Unexpected message during asset conversion'
} as const;
const T = CONVERSION_SIGNING_TEXTS;

/** The objects both sides exchange, in section 1's order. */
export type ConversionSigningField =
	| 'consent'
	| 'authorization'
	| 'final_ack'
	| 'construction_checkpoint'
	| 'exit';
type Field = ConversionSigningField;
type Chunked = 'authorization' | 'exit';

/** The local object that must have left before the peer's object of a field is taken. */
const BEFORE: Record<Field, Field | undefined> = {
	consent: undefined,
	authorization: 'consent',
	final_ack: 'authorization',
	construction_checkpoint: 'final_ack',
	exit: 'construction_checkpoint'
};

/** The signing objects of one attempt, by side and field, with the peer's chunk receivers. */
export class ConversionSigningExchange {
	private readonly local = new Map<Field, Buffer>();
	private readonly peer = new Map<Field, Buffer>();
	private readonly receivers = new Map<Chunked, AssetOpenObjectReceiver>();

	constructor(
		private readonly attempt: Buffer,
		private readonly agreement: Buffer,
		private readonly isInitiator: boolean,
		private readonly send: (subtype: number, payload: Buffer) => void
	) {}

	/** This side's object of `field`, if it left. */
	ours(field: Field): Buffer | undefined {
		return this.local.get(field);
	}

	/** The peer's object of `field`, once complete. */
	theirs(field: Field): Buffer | undefined {
		return this.peer.get(field);
	}

	/** Both objects of `field`, initiator first, once both are held. */
	both(field: Field): AssetOpenPair<Buffer> | undefined {
		const ours = this.local.get(field),
			theirs = this.peer.get(field);
		if (!ours || !theirs) return undefined;
		return this.isInitiator ? [ours, theirs] : [theirs, ours];
	}

	/** Send this side's object of `field` once: a consent, a chunked object or a digest frame. */
	publish(field: Field, bytes: Buffer): void {
		if (this.local.has(field)) return;
		const value = Buffer.from(bytes);
		this.local.set(field, value);
		if (field === 'consent') {
			this.send(
				Sub.ASSET_SPLICE_CONSENT,
				encodeAssetOpenConsent({
					attempt: this.attempt,
					digest: this.agreement,
					signature: value
				})
			);
			return;
		}
		const digestOnly =
			field === 'final_ack' || field === 'construction_checkpoint';
		const total = digestOnly ? 0 : value.length;
		const digest = digestOnly ? value : sha256(value);
		for (
			let offset = 0;
			offset < Math.max(total, 1);
			offset += ASSET_OPEN_CHUNK_SIZE
		)
			this.send(
				Sub.ASSET_SPLICE,
				encodeAssetOpenFrame({
					phase: field,
					attempt: this.attempt,
					digest,
					total,
					offset,
					bytes: digestOnly
						? Buffer.alloc(0)
						: value.subarray(offset, offset + ASSET_OPEN_CHUNK_SIZE)
				})
			);
	}

	/** The peer's consent (subtype 99). True once it is new and complete. */
	receiveConsent(raw: Buffer): boolean {
		let signature: Buffer;
		try {
			const c = decodeAssetOpenConsent(raw);
			if (!c.attempt.equals(this.attempt) || !c.digest.equals(this.agreement))
				throw new Error(T.consent);
			signature = Buffer.from(c.signature);
		} catch {
			throw new Error(T.consent);
		}
		return this.take('consent', signature);
	}

	/**
	 * The peer's frame of subtype 98 (phases 1, 3, 5 and 6). True once an
	 * object is new and complete. A phase 2 frame is unexpected: a conversion
	 * has no HTLC on either branch.
	 */
	receiveFrame(raw: Buffer): boolean {
		let frame: ReturnType<typeof decodeAssetOpenFrame>;
		try {
			frame = decodeAssetOpenFrame(raw);
		} catch {
			throw new Error(T.frame);
		}
		if (!frame.attempt.equals(this.attempt)) throw new Error(T.frame);
		switch (frame.phase) {
			case 'final_ack':
			case 'construction_checkpoint':
				return this.take(frame.phase, Buffer.from(frame.digest));
			case 'authorization':
			case 'exit': {
				const field: Chunked = frame.phase;
				this.premature(field);
				const saved = this.peer.get(field);
				if (saved) {
					if (
						frame.total !== saved.length ||
						!frame.digest.equals(sha256(saved)) ||
						!saved
							.subarray(frame.offset, frame.offset + frame.bytes.length)
							.equals(frame.bytes)
					)
						throw new Error(T.conflicting);
					return false;
				}
				let receiver = this.receivers.get(field);
				if (!receiver) {
					receiver = new AssetOpenObjectReceiver(
						this.attempt,
						field,
						ASSET_OPEN_OBJECT_LIMIT
					);
					this.receivers.set(field, receiver);
				}
				let complete: Buffer | undefined;
				try {
					complete = receiver.receive(frame);
				} catch {
					throw new Error(T.frame);
				}
				if (!complete) return false;
				this.receivers.delete(field);
				return this.take(field, complete);
			}
			default:
				throw new Error(T.unexpected);
		}
	}

	/** Refuse a peer object whose local predecessor has not left. */
	private premature(field: Field): void {
		const before = BEFORE[field];
		if (before && !this.local.has(before)) throw new Error(T.premature);
	}

	/** Keep the peer's object; an identical copy is dropped and a different one refused. */
	private take(field: Field, bytes: Buffer): boolean {
		this.premature(field);
		const saved = this.peer.get(field);
		if (saved) {
			if (!saved.equals(bytes)) throw new Error(T.conflicting);
			return false;
		}
		this.peer.set(field, Buffer.from(bytes));
		return true;
	}
}
