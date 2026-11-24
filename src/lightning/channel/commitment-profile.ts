/** A stored profile this wallet or recovery format cannot represent. */
export class UnsupportedCommitmentProfileError extends Error {}

/** Exact final channel type, with or without the SCID alias modifier. */
export function isFinalTaprootTypeHex(value: unknown): boolean {
	return (
		value === '0100000000000000000000' || value === '0100000000400000000000'
	);
}

export function hasCommitmentProfile(row: unknown): boolean {
	return row !== null && typeof row === 'object' && 'commitmentProfile' in row;
}

/** Old formats persisted unmarked channel types, including bits 80 and 81, as legacy. */
export function assertLegacyCommitmentProfile(row: unknown): void {
	if (hasCommitmentProfile(row)) {
		throw new UnsupportedCommitmentProfileError(
			'Unsupported channel commitment profile in this format'
		);
	}
}
