/**
 * The Porch links a daemon serves. Every node has one link from its seed, so
 * it returns with the seed; the others are made on request, each with a
 * random tag, so one can be handed to one person and taken back without
 * touching the rest. Revoking is remembered here: a link that came back
 * after a restart would be worse than one that was never revoked.
 */
import { randomBytes } from 'crypto';
import { PORCH_MAX_TAGS, PORCH_TAG_BYTES } from '../lightning/transport/porch';

/** Longest label a link can carry, in characters. */
export const PORCH_LINK_LABEL_MAX = 64;

/** A link as the daemon keeps it. The id is the link's tag, hex. */
export interface IPorchLinkRecord {
	id: string;
	/** The link from the seed. */
	default?: true;
	label?: string;
	/** Unix ms. The seed's link has none. */
	createdAt?: number;
}

/** Where the store keeps its one JSON value. */
export interface IPorchLinkStorage {
	load(): string | null;
	save(value: string): void;
}

interface IStoredLink {
	tag: string;
	label?: string;
	createdAt: number;
}

interface IStoredLinks {
	defaultRevoked: boolean;
	links: IStoredLink[];
}

const TAG_HEX = new RegExp(`^[0-9a-f]{${PORCH_TAG_BYTES * 2}}$`);

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * A label is for the operator's eyes: printable text, trimmed. Returns
 * undefined for none, and throws on one that could not be shown as given.
 */
export function porchLinkLabel(label: unknown): string | undefined {
	if (label === undefined || label === null) return undefined;
	if (typeof label !== 'string') throw new Error('label must be a string');
	const trimmed = label.trim();
	if (trimmed.length === 0) return undefined;
	if (trimmed.length > PORCH_LINK_LABEL_MAX) {
		throw new Error(`label must be at most ${PORCH_LINK_LABEL_MAX} characters`);
	}
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
		throw new Error('label must not contain control characters');
	}
	return trimmed;
}

function parseStored(
	raw: string,
	defaultTag: string
): IStoredLinks | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return undefined;
	}
	if (!isRecord(parsed) || !Array.isArray(parsed.links)) return undefined;
	if (
		parsed.defaultRevoked !== undefined &&
		typeof parsed.defaultRevoked !== 'boolean'
	) {
		return undefined;
	}
	const links: IStoredLink[] = [];
	const seen = new Set<string>([defaultTag]);
	for (const entry of parsed.links as unknown[]) {
		if (!isRecord(entry)) return undefined;
		const { tag, label, createdAt } = entry;
		if (typeof tag !== 'string' || !TAG_HEX.test(tag) || seen.has(tag)) {
			return undefined;
		}
		if (label !== undefined && typeof label !== 'string') return undefined;
		if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) {
			return undefined;
		}
		seen.add(tag);
		links.push({ tag, createdAt, ...(label !== undefined ? { label } : {}) });
	}
	const defaultRevoked = parsed.defaultRevoked === true;
	// More than a registration can list: the node could not serve them.
	if (links.length + (defaultRevoked ? 0 : 1) > PORCH_MAX_TAGS) {
		return undefined;
	}
	return { defaultRevoked, links };
}

export class PorchLinkStore {
	private readonly defaultTag: string;
	private state: IStoredLinks;
	private unread: boolean;

	constructor(
		defaultTag: Uint8Array,
		private readonly storage: IPorchLinkStorage
	) {
		if (defaultTag.length !== PORCH_TAG_BYTES) {
			throw new Error(`Porch link tag must be ${PORCH_TAG_BYTES} bytes`);
		}
		this.defaultTag = Buffer.from(defaultTag).toString('hex');
		const raw = storage.load();
		const stored =
			raw === null
				? { defaultRevoked: false, links: [] }
				: parseStored(raw, this.defaultTag);
		this.unread = stored === undefined;
		this.state = stored ?? { defaultRevoked: true, links: [] };
	}

	/**
	 * True while what was stored could not be read. Nothing is served then:
	 * which links were revoked is not known, and serving one that was is the
	 * failure this store exists to prevent. Making a link starts it afresh,
	 * with the seed's link left revoked.
	 */
	get unreadable(): boolean {
		return this.unread;
	}

	/** The tags to serve now. */
	tags(): Buffer[] {
		return this.list().map((link) => Buffer.from(link.id, 'hex'));
	}

	/** The seed's link first, unless it was revoked, then the rest by age. */
	list(): IPorchLinkRecord[] {
		const links: IPorchLinkRecord[] = [];
		if (!this.state.defaultRevoked) {
			links.push({ id: this.defaultTag, default: true });
		}
		for (const link of this.state.links) {
			links.push({
				id: link.tag,
				createdAt: link.createdAt,
				...(link.label !== undefined ? { label: link.label } : {})
			});
		}
		return links;
	}

	/** Make a link with a tag of its own. Written before it is returned. */
	create(label?: string, now = Date.now()): IPorchLinkRecord {
		if (this.list().length >= PORCH_MAX_TAGS) {
			throw new Error(
				`A node serves at most ${PORCH_MAX_TAGS} Porch links; revoke one first`
			);
		}
		let tag: string;
		do {
			tag = randomBytes(PORCH_TAG_BYTES).toString('hex');
		} while (
			tag === this.defaultTag ||
			this.state.links.some((link) => link.tag === tag)
		);
		const link: IStoredLink = {
			tag,
			createdAt: now,
			...(label !== undefined ? { label } : {})
		};
		this.write({ ...this.state, links: [...this.state.links, link] });
		return {
			id: tag,
			createdAt: now,
			...(label !== undefined ? { label } : {})
		};
	}

	/**
	 * Stop serving a link, for good: the seed's link stays revoked, and a
	 * made link's tag is forgotten. Written before it returns. False when no
	 * such link is served.
	 */
	revoke(id: string): boolean {
		if (id === this.defaultTag) {
			if (this.state.defaultRevoked) return false;
			this.write({ ...this.state, defaultRevoked: true });
			return true;
		}
		const links = this.state.links.filter((link) => link.tag !== id);
		if (links.length === this.state.links.length) return false;
		this.write({ ...this.state, links });
		return true;
	}

	/** Storage first: a change that was not written did not happen. */
	private write(next: IStoredLinks): void {
		this.storage.save(JSON.stringify(next));
		this.state = next;
		this.unread = false;
	}
}
