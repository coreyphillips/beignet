import { sha256 } from '../crypto/provider';

const phases = [
	'layout',
	'authorization',
	'final',
	'exit',
	'layout_ack',
	'final_ack',
	'construction_checkpoint',
	// An asset conversion's terms and its reply (#2151), on subtype 98 only.
	'conversion_terms',
	'conversion_reply'
] as const;
type Phase = (typeof phases)[number];
/** The phases that carry a chunked object. */
const objectPhases = [
	'layout',
	'authorization',
	'final',
	'exit',
	'conversion_terms'
] as const;
type ObjectPhase = (typeof objectPhases)[number];
const HEADER = 74;
export const ASSET_OPEN_CHUNK_SIZE = 32 * 1024;
export const ASSET_OPEN_OBJECT_LIMIT = 4 * 1024 * 1024;
/** The largest conversion_terms object. */
const CONVERSION_TERMS_LIMIT = 65536;
/** A conversion_reply: a one-byte verdict and a reason of at most 200 bytes. */
const CONVERSION_REPLY_LIMIT = 201;

export interface IAssetOpenConsent {
	attempt: Buffer;
	digest: Buffer;
	signature: Buffer;
}

export function encodeAssetOpenConsent({
	attempt,
	digest,
	signature
}: IAssetOpenConsent): Buffer {
	if (
		!Buffer.isBuffer(attempt) ||
		attempt.length !== 32 ||
		!Buffer.isBuffer(digest) ||
		digest.length !== 32 ||
		!Buffer.isBuffer(signature) ||
		signature.length !== 64
	)
		throw new Error('Invalid asset opening consent');
	return Buffer.concat([Buffer.of(1), attempt, digest, signature]);
}

export function decodeAssetOpenConsent(raw: Buffer): IAssetOpenConsent {
	if (!Buffer.isBuffer(raw) || raw.length !== 129 || raw[0] !== 1)
		throw new Error('Invalid asset opening consent');
	return {
		attempt: raw.subarray(1, 33),
		digest: raw.subarray(33, 65),
		signature: raw.subarray(65)
	};
}

export interface IAssetOpenFrame {
	phase: Phase;
	attempt: Buffer;
	digest: Buffer;
	total: number;
	offset: number;
	bytes: Buffer;
}

function validateFrame(frame: IAssetOpenFrame): void {
	const { phase, attempt, digest, total, offset, bytes } = frame;
	if (
		!phases.includes(phase) ||
		!Buffer.isBuffer(attempt) ||
		attempt.length !== 32 ||
		!Buffer.isBuffer(digest) ||
		digest.length !== 32 ||
		!Buffer.isBuffer(bytes)
	)
		throw new Error('Invalid asset opening frame');
	if (
		(phase === 'conversion_reply' &&
			(offset !== 0 ||
				total !== bytes.length ||
				total < 1 ||
				total > CONVERSION_REPLY_LIMIT)) ||
		(phase === 'conversion_terms' && total > CONVERSION_TERMS_LIMIT)
	)
		throw new Error('Invalid asset conversion frame');
	if (phase === 'conversion_reply') return;
	if (
		phase === 'layout_ack' ||
		phase === 'final_ack' ||
		phase === 'construction_checkpoint'
	) {
		if (total !== 0 || offset !== 0 || bytes.length !== 0)
			throw new Error(
				'Asset opening acknowledgement must contain only its digest'
			);
		return;
	}
	if (
		!Number.isInteger(total) ||
		total < 1 ||
		total > ASSET_OPEN_OBJECT_LIMIT ||
		!Number.isInteger(offset) ||
		offset < 0 ||
		offset >= total ||
		offset % ASSET_OPEN_CHUNK_SIZE !== 0 ||
		bytes.length !== Math.min(ASSET_OPEN_CHUNK_SIZE, total - offset)
	)
		throw new Error('Invalid asset opening chunk bounds');
}

export function encodeAssetOpenFrame(frame: IAssetOpenFrame): Buffer {
	validateFrame(frame);
	const raw = Buffer.allocUnsafe(HEADER + frame.bytes.length);
	raw[0] = 1;
	raw[1] = phases.indexOf(frame.phase);
	frame.attempt.copy(raw, 2);
	frame.digest.copy(raw, 34);
	raw.writeUInt32BE(frame.total, 66);
	raw.writeUInt32BE(frame.offset, 70);
	frame.bytes.copy(raw, HEADER);
	return raw;
}

export function decodeAssetOpenFrame(raw: Buffer): IAssetOpenFrame {
	if (
		!Buffer.isBuffer(raw) ||
		raw.length < HEADER ||
		raw.length > HEADER + ASSET_OPEN_CHUNK_SIZE ||
		raw[0] !== 1
	)
		throw new Error('Invalid asset opening frame version or size');
	const frame = {
		phase: phases[raw[1]],
		attempt: raw.subarray(2, 34),
		digest: raw.subarray(34, 66),
		total: raw.readUInt32BE(66),
		offset: raw.readUInt32BE(70),
		bytes: raw.subarray(HEADER)
	};
	validateFrame(frame);
	return frame;
}

/** Assemble one authorized peer's object. Storage grows only as its bytes arrive. */
export class AssetOpenObjectReceiver {
	private readonly attempt: Buffer;
	private readonly chunks: Buffer[] = [];
	private received = 0;
	private total = 0;
	private digest?: Buffer;

	constructor(
		attempt: Buffer,
		private readonly phase: ObjectPhase,
		private readonly maxBytes: number
	) {
		if (
			!Buffer.isBuffer(attempt) ||
			attempt.length !== 32 ||
			!(objectPhases as readonly string[]).includes(phase) ||
			!Number.isInteger(maxBytes) ||
			maxBytes < 1 ||
			maxBytes > ASSET_OPEN_OBJECT_LIMIT
		)
			throw new Error('Invalid asset opening object receiver');
		this.attempt = Buffer.from(attempt);
	}

	receive(frame: IAssetOpenFrame): Buffer | undefined {
		validateFrame(frame);
		if (
			!frame.attempt.equals(this.attempt) ||
			frame.phase !== this.phase ||
			frame.total > this.maxBytes ||
			frame.offset > this.received ||
			(this.digest &&
				(!frame.digest.equals(this.digest) || frame.total !== this.total))
		)
			throw new Error('Unexpected asset opening object chunk');
		if (frame.offset < this.received) {
			if (
				!this.chunks[frame.offset / ASSET_OPEN_CHUNK_SIZE].equals(frame.bytes)
			)
				throw new Error('Conflicting asset opening chunk replay');
			return;
		}
		let complete: Buffer | undefined;
		if (frame.offset + frame.bytes.length === frame.total) {
			complete = Buffer.concat([...this.chunks, frame.bytes], frame.total);
			if (!sha256(complete).equals(frame.digest))
				throw new Error('Asset opening object digest mismatch');
		}
		if (!this.digest) {
			this.total = frame.total;
			this.digest = Buffer.from(frame.digest);
		}
		this.chunks.push(Buffer.from(frame.bytes));
		this.received += frame.bytes.length;
		return complete;
	}
}
