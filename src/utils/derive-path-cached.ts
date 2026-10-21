import { BIP32Interface } from 'bip32';

// The grammar derivePath accepts: an optional "m/", then decimal segments,
// each hardened by a trailing apostrophe.
const BIP32_PATH = /^(m\/)?(\d+'?\/)*\d+'?$/;

/**
 * Derives `path` from `node` exactly as `node.derivePath(path)` does, but
 * reads and fills `branches` with every node above the leaf, keyed by its
 * path prefix. Addresses on one account and change branch share all but
 * their last step, so with the branch held each costs one derivation
 * instead of five. The leaf is never stored, so callers get a node of their
 * own. A `branches` map must only ever be used with one `node`.
 * @param {BIP32Interface} node
 * @param {string} path
 * @param {Map<string, BIP32Interface>} branches
 * @returns {BIP32Interface}
 */
export const derivePathCached = (
	node: BIP32Interface,
	path: string,
	branches: Map<string, BIP32Interface>
): BIP32Interface => {
	// derivePath refuses these, so it is left to throw its own error.
	if (
		!BIP32_PATH.test(path) ||
		(path.startsWith('m/') && node.parentFingerprint)
	) {
		return node.derivePath(path);
	}
	const cut = path.lastIndexOf('/');
	if (cut === -1) return deriveSegment(node, path);
	return deriveSegment(
		branchNode(node, path.slice(0, cut), branches),
		path.slice(cut + 1)
	);
};

const branchNode = (
	node: BIP32Interface,
	prefix: string,
	branches: Map<string, BIP32Interface>
): BIP32Interface => {
	if (prefix === 'm') return node;
	let branch = branches.get(prefix);
	if (branch) return branch;
	const cut = prefix.lastIndexOf('/');
	const parent =
		cut === -1 ? node : branchNode(node, prefix.slice(0, cut), branches);
	branch = deriveSegment(parent, prefix.slice(cut + 1));
	branches.set(prefix, branch);
	return branch;
};

const deriveSegment = (
	node: BIP32Interface,
	segment: string
): BIP32Interface =>
	segment.endsWith("'")
		? node.deriveHardened(parseInt(segment.slice(0, -1), 10))
		: node.derive(parseInt(segment, 10));
