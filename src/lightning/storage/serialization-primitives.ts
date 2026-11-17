/** JSON-safe encodings of the primitive types every storage codec shares. */

export function bufToHex(buf: Buffer | null | undefined): string | null {
	return buf ? buf.toString('hex') : null;
}

export function hexToBuf(hex: string | null | undefined): Buffer | null {
	return hex ? Buffer.from(hex, 'hex') : null;
}

export function bigintToStr(val: bigint): string {
	return val.toString();
}

export function strToBigint(val: string): bigint {
	return BigInt(val);
}
