/**
 * Hash constructions shared across the Lightning layer. They hash through the
 * crypto provider, so a host-installed provider covers them too.
 */

import { sha256 } from './provider';

/**
 * BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || messages...).
 * A string tag is hashed as its UTF-8 bytes. A byte tag is taken as is,
 * because BOLT 12 builds its nonce tag from a TLV record.
 */
export function taggedHash(
	tag: string | Uint8Array,
	...messages: Uint8Array[]
): Buffer {
	const tagHash = sha256(
		typeof tag === 'string' ? Buffer.from(tag, 'utf8') : tag
	);
	return sha256(Buffer.concat([tagHash, tagHash, ...messages]));
}
