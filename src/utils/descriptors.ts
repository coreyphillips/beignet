/**
 * BIP 380 output-script-descriptor checksum.
 *
 * Descriptors exported with a trailing #checksum are directly importable by
 * Bitcoin Core (importdescriptors) and most descriptor-aware tooling.
 */

// Characters a descriptor may contain, in the order BIP 380 assigns symbols.
const INPUT_CHARSET =
	'0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const GENERATOR = [
	0xf5dee51989n,
	0xa9fdca3312n,
	0x1bab10e32dn,
	0x3706b1677an,
	0x644d626ffdn
];

const polymod = (c: bigint, val: bigint): bigint => {
	const c0 = c >> 35n;
	let next = ((c & 0x7ffffffffn) << 5n) ^ val;
	for (let i = 0; i < 5; i++) {
		if ((c0 >> BigInt(i)) & 1n) next ^= GENERATOR[i];
	}
	return next;
};

/**
 * Computes the 8-character BIP 380 checksum for a descriptor body (the part
 * before '#'). Returns null when the descriptor contains characters outside
 * the descriptor charset.
 * @param {string} descriptor
 * @returns {string | null}
 */
export const descriptorChecksum = (descriptor: string): string | null => {
	let c = 1n;
	let cls = 0n;
	let clsCount = 0;
	for (const ch of descriptor) {
		const pos = INPUT_CHARSET.indexOf(ch);
		if (pos === -1) return null;
		c = polymod(c, BigInt(pos & 31));
		cls = cls * 3n + BigInt(pos >> 5);
		clsCount += 1;
		if (clsCount === 3) {
			c = polymod(c, cls);
			cls = 0n;
			clsCount = 0;
		}
	}
	if (clsCount > 0) c = polymod(c, cls);
	for (let j = 0; j < 8; j++) c = polymod(c, 0n);
	c ^= 1n;
	let checksum = '';
	for (let j = 0; j < 8; j++) {
		checksum += CHECKSUM_CHARSET[Number((c >> (5n * (7n - BigInt(j)))) & 31n)];
	}
	return checksum;
};

/**
 * Appends the BIP 380 checksum ("body#checksum") when computable; returns the
 * body unchanged otherwise.
 * @param {string} descriptor
 * @returns {string}
 */
export const appendDescriptorChecksum = (descriptor: string): string => {
	const checksum = descriptorChecksum(descriptor);
	return checksum ? `${descriptor}#${checksum}` : descriptor;
};
