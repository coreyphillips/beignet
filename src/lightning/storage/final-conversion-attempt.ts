/**
 * The attempt records of an asset conversion (#2151 Step 4a). From the
 * moment a side sends its `layout_ack`, its attempt is on disk in the
 * device-journal scope `conversion-attempt`, and the side withdraws it when
 * the attempt ends. The scope alternates a `conversion-attempt` and a
 * `conversion-withdrawn` row, so an attempt is open exactly when the scope's
 * last row is a `conversion-attempt`, which is exactly when its row count is
 * odd. Attempt ids repeat (identical terms on an unchanged parent give the
 * same id), so a record is named by its scope sequence, not by its id.
 *
 * Nothing that claims a commitment or refuses a restore counts this scope:
 * nothing in it is signed.
 */

/** The fields of a `conversion-attempt` row, every byte string in lowercase hex. */
export interface IConversionAttemptFields {
	/** The attempt id, 32 bytes. */
	attempt: string;
	/** The peer's node id, 33 bytes. */
	peer: string;
	isInitiator: boolean;
	isOpener: boolean;
	/** The quote giver, from the terms. */
	giver: 'opener' | 'acceptor';
	direction: 'to-plain' | 'to-asset';
	/** The snapshot's parent, as in IAssetConversionContext.parent. */
	parent: {
		txid: string;
		outputIndex: number;
		stateNumber: string;
		type: 'plain' | 'asset';
		channelType: string;
	};
	/** 32 bytes each. */
	termsDigest: string;
	layoutDigest: string;
	planDigest: string;
	/** The agreement digest the side sent in its `layout_ack`. */
	agreement: string;
	/** The candidate funding key's index. */
	keyIndex: number;
}

export type FinalConversionAttemptEvent =
	| ({ kind: 'conversion-attempt' } & IConversionAttemptFields)
	| { kind: 'conversion-withdrawn'; attempt: string; reason: string };

/** The open record, with its scope sequence. */
export type IOpenConversionAttempt = IConversionAttemptFields & {
	sequence: number;
};

/** One channel the startup sweep found open. */
export interface ISweptConversionAttempt {
	channelId: string;
	/** The open record's scope sequence. */
	sequence: number;
	/** The open record, once it could be read. */
	record?: IConversionAttemptFields;
	/** Why the withdrawal could not be written; absent once it was. */
	error?: string;
}

export const CONVERSION_ATTEMPT_TEXTS = {
	topLevel: 'Conversion attempts require a top-level commit',
	wallet: 'Conversion attempts require an original conversion wallet',
	notRecorded: 'Conversion attempt was not recorded',
	invalid: 'Invalid conversion attempt record',
	open: 'Another conversion of this channel is in progress'
} as const;

/** A canonical reason's limit in bytes, the conversion's REASON_LIMIT. */
export const CONVERSION_REASON_LIMIT = 200;

/**
 * The canonical form of a reason (amendment A4): each byte of the text's
 * UTF-8 bytes (or of the raw bytes given) from 0x20 to 0x7e except `\` is
 * kept, and every other byte is written `\xNN` in lowercase hex; the result
 * is cut to at most 200 bytes, never inside an escape. It always escapes, so
 * it is not the decline reason's reader, which passes valid UTF-8 through.
 */
export function canonicalConversionReason(text: string | Uint8Array): string {
	const bytes =
		typeof text === 'string' ? Buffer.from(text, 'utf8') : Buffer.from(text);
	let out = '';
	for (const b of bytes) {
		const token =
			b >= 0x20 && b <= 0x7e && b !== 0x5c
				? String.fromCharCode(b)
				: '\\x' + b.toString(16).padStart(2, '0');
		if (out.length + token.length > CONVERSION_REASON_LIMIT) break;
		out += token;
	}
	return out;
}

/** The bytes a canonical reason names, or undefined for a text outside its alphabet. */
function reasonBytes(text: string): Buffer | undefined {
	const bytes: number[] = [];
	for (let i = 0; i < text.length; ) {
		const c = text.charCodeAt(i);
		if (c === 0x5c) {
			const escape = /^\\x([0-9a-f]{2})/.exec(text.slice(i, i + 4));
			if (!escape) return undefined;
			bytes.push(parseInt(escape[1], 16));
			i += 4;
		} else if (c >= 0x20 && c <= 0x7e) {
			bytes.push(c);
			i += 1;
		} else return undefined;
	}
	return Buffer.from(bytes);
}

/** Whether `text` is exactly a canonical reason: the form canonicalConversionReason gives. */
export function isCanonicalConversionReason(text: unknown): text is string {
	if (typeof text !== 'string' || text.length > CONVERSION_REASON_LIMIT)
		return false;
	const bytes = reasonBytes(text);
	return !!bytes && canonicalConversionReason(bytes) === text;
}

function invalid(): never {
	throw new Error(CONVERSION_ATTEMPT_TEXTS.invalid);
}
function check(condition: unknown): asserts condition {
	if (!condition) invalid();
}
/** Exactly these keys, no other. */
function keys(v: unknown, required: readonly string[]): void {
	check(v !== null && typeof v === 'object' && !Array.isArray(v));
	const present = Object.keys(v as object);
	check(
		present.length === required.length &&
			required.every((k) => present.includes(k))
	);
}
function hex(v: unknown, bytes?: number): string {
	check(
		typeof v === 'string' &&
			v.length > 0 &&
			v.length % 2 === 0 &&
			/^[0-9a-f]+$/.test(v) &&
			(bytes === undefined || v.length === bytes * 2)
	);
	return v;
}
function index(v: unknown): number {
	check(
		Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= 0xffffffff
	);
	return v as number;
}
function decimal(v: unknown): string {
	check(
		typeof v === 'string' &&
			v.length <= 20 &&
			/^(0|[1-9][0-9]*)$/.test(v) &&
			BigInt(v) <= 0xffffffffffffffffn
	);
	return v;
}
function flag(v: unknown): boolean {
	check(typeof v === 'boolean');
	return v;
}
function oneOf<V extends string>(v: unknown, values: readonly V[]): V {
	check(typeof v === 'string' && (values as readonly string[]).includes(v));
	return v as V;
}

const FIELDS = [
	'attempt',
	'peer',
	'isInitiator',
	'isOpener',
	'giver',
	'direction',
	'parent',
	'termsDigest',
	'layoutDigest',
	'planDigest',
	'agreement',
	'keyIndex'
] as const;
const PARENT = [
	'txid',
	'outputIndex',
	'stateNumber',
	'type',
	'channelType'
] as const;

/** The checked fields of an attempt record in a fixed key order: no unknown field, every length exact. */
function fields(v: Record<string, unknown>): IConversionAttemptFields {
	const p = v.parent as Record<string, unknown>;
	keys(p, PARENT);
	return {
		attempt: hex(v.attempt, 32),
		peer: hex(v.peer, 33),
		isInitiator: flag(v.isInitiator),
		isOpener: flag(v.isOpener),
		giver: oneOf(v.giver, ['opener', 'acceptor'] as const),
		direction: oneOf(v.direction, ['to-plain', 'to-asset'] as const),
		parent: {
			txid: hex(p.txid, 32),
			outputIndex: index(p.outputIndex),
			stateNumber: decimal(p.stateNumber),
			type: oneOf(p.type, ['plain', 'asset'] as const),
			channelType: hex(p.channelType)
		},
		termsDigest: hex(v.termsDigest, 32),
		layoutDigest: hex(v.layoutDigest, 32),
		planDigest: hex(v.planDigest, 32),
		agreement: hex(v.agreement, 32),
		keyIndex: index(v.keyIndex)
	};
}

/** The writer's input, checked: the fields of section 2.2 without the `kind`. */
export function canonicalConversionAttempt(
	v: unknown
): IConversionAttemptFields {
	keys(v, FIELDS);
	return fields(v as Record<string, unknown>);
}

/** A stored event, checked strictly: an unknown field, a wrong length or a reason that is not canonical refuses it. */
export function canonicalConversionAttemptEvent(
	v: unknown
): FinalConversionAttemptEvent {
	const e = v as Record<string, unknown> | null;
	if (e?.kind === 'conversion-withdrawn') {
		keys(e, ['kind', 'attempt', 'reason']);
		check(isCanonicalConversionReason(e.reason));
		return {
			kind: 'conversion-withdrawn',
			attempt: hex(e.attempt, 32),
			reason: e.reason
		};
	}
	check(e?.kind === 'conversion-attempt');
	keys(e, ['kind', ...FIELDS]);
	return { kind: 'conversion-attempt', ...fields(e) };
}

/**
 * A channel's events, oldest first, checked one by one and as a scope: they
 * alternate a record and the withdrawal of that same record.
 */
export function checkedConversionAttempts(
	records: readonly unknown[]
): FinalConversionAttemptEvent[] {
	const events = records.map(canonicalConversionAttemptEvent);
	events.forEach((e, i) => {
		if (i % 2 === 0) check(e.kind === 'conversion-attempt');
		else
			check(
				e.kind === 'conversion-withdrawn' && e.attempt === events[i - 1].attempt
			);
	});
	return events;
}

/** Whether two attempt records are equal in every field. */
export function sameConversionAttempt(
	a: IConversionAttemptFields,
	b: IConversionAttemptFields
): boolean {
	try {
		return (
			JSON.stringify(canonicalConversionAttempt(a)) ===
			JSON.stringify(canonicalConversionAttempt(b))
		);
	} catch {
		return false;
	}
}
